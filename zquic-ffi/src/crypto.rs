//! ZCrypto Integration - Cryptographic operations for ZQUIC
//! Provides Ed25519, Blake3, and other crypto operations

use super::*;
use std::slice;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::RngCore;
use sha2::{Sha256, Digest};
use blake3::Hasher as Blake3Hasher;

/// Cryptographic key types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum KeyType {
    Ed25519 = 1,
    Secp256k1 = 2,
    X25519 = 3,
}

/// Cryptographic hash types
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum HashType {
    Blake3 = 1,
    Sha256 = 2,
    Sha3 = 3,
}

/// Cryptographic operation result
#[repr(C)]
pub struct CryptoResult {
    pub status: c_int,
    pub error_message: *mut c_char,
    pub data_len: usize,
}

impl CryptoResult {
    pub fn new() -> Self {
        Self {
            status: ZQUIC_OK,
            error_message: ptr::null_mut(),
            data_len: 0,
        }
    }
    
    pub fn with_error(error: &str) -> Self {
        let error_msg = to_c_string(error).unwrap_or_default();
        Self {
            status: ZQUIC_ERROR_CRYPTO,
            error_message: error_msg.into_raw(),
            data_len: 0,
        }
    }
}

/// Initialize crypto subsystem
#[no_mangle]
pub extern "C" fn zquic_crypto_init() -> c_int {
    info!("🔐 ZCrypto subsystem initialized");
    ZQUIC_OK
}

/// Generate cryptographic key pair
#[no_mangle]
pub extern "C" fn zquic_crypto_keygen(
    key_type: u8,
    public_key: *mut u8,
    private_key: *mut u8,
    result: *mut CryptoResult,
) -> c_int {
    if public_key.is_null() || private_key.is_null() || result.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        *result = CryptoResult::new();
    }
    
    // Security audit for crypto operation - log the crypto operation
    debug!("🔐 Performing Ed25519 key generation");

    match KeyType::from(key_type) {
        Some(KeyType::Ed25519) => {
            let _rng = rand::thread_rng();
            let mut key_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key_bytes);
            let signing_key = SigningKey::from_bytes(&key_bytes);
            let verifying_key = signing_key.verifying_key();
            
            unsafe {
                // Copy public key (32 bytes)
                std::ptr::copy_nonoverlapping(
                    verifying_key.as_bytes().as_ptr(),
                    public_key,
                    32,
                );
                
                // Copy private key (32 bytes) - ensure secure handling
                std::ptr::copy_nonoverlapping(
                    signing_key.as_bytes().as_ptr(),
                    private_key,
                    32,
                );
                
                // Security note: Private key material copied to user-provided buffer
                // User is responsible for secure handling and zeroing after use
                debug!("🔑 Private key material copied to user buffer");
                
                (*result).data_len = 32;
            }
            
            debug!("🔑 Generated Ed25519 key pair");
            ZQUIC_OK
        }
        Some(KeyType::Secp256k1) => {
            // TODO: Implement secp256k1 key generation
            unsafe {
                *result = CryptoResult::with_error("Secp256k1 not yet implemented");
            }
            ZQUIC_ERROR_CRYPTO
        }
        Some(KeyType::X25519) => {
            // TODO: Implement X25519 key generation  
            unsafe {
                *result = CryptoResult::with_error("X25519 not yet implemented");
            }
            ZQUIC_ERROR_CRYPTO
        }
        None => {
            unsafe {
                *result = CryptoResult::with_error("Invalid key type");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
    }
}

/// Sign data with private key
#[no_mangle]
pub extern "C" fn zquic_crypto_sign(
    key_type: u8,
    private_key: *const u8,
    data: *const u8,
    data_len: usize,
    signature: *mut u8,
    result: *mut CryptoResult,
) -> c_int {
    if private_key.is_null() || data.is_null() || signature.is_null() || result.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    // Validate data size to prevent potential DoS attacks
    if data_len > 1024 * 1024 { // 1MB limit
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        *result = CryptoResult::new();
    }
    
    debug!("🔐 Performing signature operation on {} bytes", data_len);

    match KeyType::from(key_type) {
        Some(KeyType::Ed25519) => {
            let private_key_bytes = unsafe { slice::from_raw_parts(private_key, 32) };
            let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
            
            match SigningKey::try_from(private_key_bytes) {
                Ok(signing_key) => {
                    let sig = signing_key.sign(data_bytes);
                    
                    unsafe {
                        // Copy signature (64 bytes)
                        std::ptr::copy_nonoverlapping(
                            sig.to_bytes().as_ptr(),
                            signature,
                            64,
                        );
                        
                        (*result).data_len = 64;
                    }
                    
                    debug!("✍️  Signed {} bytes with Ed25519", data_len);
                    ZQUIC_OK
                }
                Err(e) => {
                    unsafe {
                        *result = CryptoResult::with_error(&format!("Invalid private key: {}", e));
                    }
                    ZQUIC_ERROR_CRYPTO
                }
            }
        }
        Some(KeyType::Secp256k1) => {
            unsafe {
                *result = CryptoResult::with_error("Secp256k1 signing not yet implemented");
            }
            ZQUIC_ERROR_CRYPTO
        }
        Some(KeyType::X25519) => {
            unsafe {
                *result = CryptoResult::with_error("X25519 is for key exchange, not signing");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
        None => {
            unsafe {
                *result = CryptoResult::with_error("Invalid key type");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
    }
}

/// Verify signature
#[no_mangle]
pub extern "C" fn zquic_crypto_verify(
    key_type: u8,
    public_key: *const u8,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
    result: *mut CryptoResult,
) -> c_int {
    if public_key.is_null() || data.is_null() || signature.is_null() || result.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    // Validate data size to prevent potential DoS attacks
    if data_len > 1024 * 1024 { // 1MB limit
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        *result = CryptoResult::new();
    }
    
    debug!("🔍 Performing signature verification on {} bytes", data_len);

    match KeyType::from(key_type) {
        Some(KeyType::Ed25519) => {
            let public_key_bytes = unsafe { slice::from_raw_parts(public_key, 32) };
            let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };
            let signature_bytes = unsafe { slice::from_raw_parts(signature, 64) };
            
            match VerifyingKey::try_from(public_key_bytes) {
                Ok(public) => {
                    match Signature::try_from(signature_bytes) {
                        Ok(sig) => {
                            match public.verify(data_bytes, &sig) {
                                Ok(_) => {
                                    debug!("✅ Ed25519 signature verified");
                                    ZQUIC_OK
                                }
                                Err(e) => {
                                    unsafe {
                                        *result = CryptoResult::with_error(&format!("Signature verification failed: {}", e));
                                    }
                                    ZQUIC_ERROR_CRYPTO
                                }
                            }
                        }
                        Err(e) => {
                            unsafe {
                                *result = CryptoResult::with_error(&format!("Invalid signature: {}", e));
                            }
                            ZQUIC_ERROR_CRYPTO
                        }
                    }
                }
                Err(e) => {
                    unsafe {
                        *result = CryptoResult::with_error(&format!("Invalid public key: {}", e));
                    }
                    ZQUIC_ERROR_CRYPTO
                }
            }
        }
        Some(KeyType::Secp256k1) => {
            unsafe {
                *result = CryptoResult::with_error("Secp256k1 verification not yet implemented");
            }
            ZQUIC_ERROR_CRYPTO
        }
        Some(KeyType::X25519) => {
            unsafe {
                *result = CryptoResult::with_error("X25519 is for key exchange, not signatures");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
        None => {
            unsafe {
                *result = CryptoResult::with_error("Invalid key type");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
    }
}

/// Hash data
#[no_mangle]
pub extern "C" fn zquic_crypto_hash(
    hash_type: u8,
    data: *const u8,
    data_len: usize,
    output: *mut u8,
    result: *mut CryptoResult,
) -> c_int {
    if data.is_null() || output.is_null() || result.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    // Validate data size to prevent potential DoS attacks
    if data_len > 10 * 1024 * 1024 { // 10MB limit for hashing
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        *result = CryptoResult::new();
    }
    
    debug!("🔢 Performing hash operation on {} bytes", data_len);

    let data_bytes = unsafe { slice::from_raw_parts(data, data_len) };

    match HashType::from(hash_type) {
        Some(HashType::Blake3) => {
            let mut hasher = Blake3Hasher::new();
            hasher.update(data_bytes);
            let hash = hasher.finalize();
            
            unsafe {
                std::ptr::copy_nonoverlapping(
                    hash.as_bytes().as_ptr(),
                    output,
                    32,
                );
                (*result).data_len = 32;
            }
            
            debug!("🔢 Blake3 hash computed for {} bytes", data_len);
            ZQUIC_OK
        }
        Some(HashType::Sha256) => {
            let mut hasher = Sha256::new();
            hasher.update(data_bytes);
            let hash = hasher.finalize();
            
            unsafe {
                std::ptr::copy_nonoverlapping(
                    hash.as_ptr(),
                    output,
                    32,
                );
                (*result).data_len = 32;
            }
            
            debug!("🔢 SHA256 hash computed for {} bytes", data_len);
            ZQUIC_OK
        }
        Some(HashType::Sha3) => {
            unsafe {
                *result = CryptoResult::with_error("SHA3 not yet implemented");
            }
            ZQUIC_ERROR_CRYPTO
        }
        None => {
            unsafe {
                *result = CryptoResult::with_error("Invalid hash type");
            }
            ZQUIC_ERROR_INVALID_PARAM
        }
    }
}

/// Free crypto result
#[no_mangle]
pub extern "C" fn zquic_crypto_result_free(result: *mut CryptoResult) -> c_int {
    if result.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        let res = &mut *result;
        if !res.error_message.is_null() {
            let _ = CString::from_raw(res.error_message);
            res.error_message = ptr::null_mut();
        }
    }

    ZQUIC_OK
}

// Helper implementations
impl KeyType {
    fn from(value: u8) -> Option<Self> {
        match value {
            1 => Some(KeyType::Ed25519),
            2 => Some(KeyType::Secp256k1),
            3 => Some(KeyType::X25519),
            _ => None,
        }
    }
}

impl HashType {
    fn from(value: u8) -> Option<Self> {
        match value {
            1 => Some(HashType::Blake3),
            2 => Some(HashType::Sha256),
            3 => Some(HashType::Sha3),
            _ => None,
        }
    }
}