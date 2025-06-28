use anyhow::Result;
use crate::gcrypt_compat as gcrypt;
use gcrypt::prelude::*;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha512};
// Keep ed25519-dalek as fallback during migration
use ed25519_dalek::{Signature as Ed25519Signature, SigningKey, VerifyingKey, Signer as Ed25519Signer, Verifier as Ed25519Verifier};

// Import realID FFI for identity operations
use crate::ffi::realid::RealIdFfi;

/// GhostChain Transaction structure for signing - following gcrypt integration guide
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostchainTransaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
}

impl GhostchainTransaction {
    /// Convert transaction to bytes for signing
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.from);
        bytes.extend_from_slice(&self.to);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
}

/// RealID signer for blockchain operations using realID Zig FFI + gcrypt
#[derive(Clone)]
pub struct RealIdSigner {
    gcrypt_keypair: KeyPair,
    // Fallback keys during migration
    ed25519_signing_key: SigningKey,
    ed25519_verifying_key: VerifyingKey,
    identity_id: String,
    realid_ffi: RealIdFfi,
    use_gcrypt: bool,
}

/// Signature structure compatible with gcrypt and Ed25519
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub data: Vec<u8>, // Gcrypt or Ed25519 signature bytes
    pub algorithm: String, // "Gcrypt-Ed25519" or "Ed25519-RealID"
    pub key_type: String,
}

/// Identity verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub identity_id: Option<String>,
    pub trust_score: Option<f64>,
    pub error: Option<String>,
}

impl RealIdSigner {
    /// Create a new RealID signer using gcrypt and realID FFI
    pub fn new() -> Result<Self> {
        info!("🔑 Initializing RealID Signer with Gcrypt");
        
        // Try to initialize gcrypt first
        let (gcrypt_keypair, use_gcrypt) = match Self::init_gcrypt_keypair() {
            Ok(keypair) => {
                info!("✅ Gcrypt initialized successfully");
                (keypair, true)
            }
            Err(e) => {
                warn!("⚠️ Gcrypt initialization failed, falling back to Ed25519: {}", e);
                (KeyPair::default(), false) // Placeholder
            }
        };
        
        // Always initialize Ed25519 as fallback
        let mut rng = OsRng;
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);
        let ed25519_signing_key = SigningKey::from_bytes(&secret_bytes);
        let ed25519_verifying_key = VerifyingKey::from(&ed25519_signing_key);
        
        // Initialize realID FFI
        let realid_ffi = RealIdFfi::new()?;
        
        // Create identity ID from public key hash
        let public_key_bytes = if use_gcrypt {
            gcrypt_keypair.public_key().as_bytes()
        } else {
            ed25519_verifying_key.as_bytes().to_vec()
        };
        
        let identity_id = {
            let mut hasher = gcrypt::hash::Hasher::new(gcrypt::hash::Algorithm::Sha512)?;
            hasher.update(&public_key_bytes);
            hasher.update(b"ghostchain-realid");
            let hash = hasher.finalize();
            hex::encode(&hash[..16]) // Use first 16 bytes as identity
        };
        
        info!("🔑 RealID Signer initialized with identity: {}", identity_id);
        info!("🔑 Using crypto backend: {}", if use_gcrypt { "Gcrypt" } else { "Ed25519" });
        info!("🔑 Public key: {}", hex::encode(&public_key_bytes));
        
        Ok(Self {
            gcrypt_keypair,
            ed25519_signing_key,
            ed25519_verifying_key,
            identity_id,
            realid_ffi,
            use_gcrypt,
        })
    }
    
    /// Initialize gcrypt keypair
    fn init_gcrypt_keypair() -> Result<KeyPair> {
        // Initialize gcrypt library
        gcrypt::init();
        
        // Generate Ed25519 keypair using gcrypt
        KeyPair::generate(gcrypt::asymmetric::Algorithm::Ed25519)
            .map_err(|e| anyhow::anyhow!("Gcrypt keypair generation failed: {}", e))
    }
    
    /// Create RealID signer from existing private key bytes
    pub fn from_private_key(private_key_bytes: &[u8]) -> Result<Self> {
        info!("🔑 Initializing RealID Signer from existing private key");
        
        if private_key_bytes.len() != 32 {
            return Err(anyhow::anyhow!("Invalid private key length: expected 32 bytes"));
        }
        
        // Always initialize Ed25519 as fallback
        let ed25519_signing_key = SigningKey::from_bytes(private_key_bytes.try_into()?);
        let ed25519_verifying_key = VerifyingKey::from(&ed25519_signing_key);
        
        // Try to initialize gcrypt
        let (gcrypt_keypair, use_gcrypt) = match Self::init_gcrypt_keypair() {
            Ok(keypair) => (keypair, true),
            Err(_) => (KeyPair::default(), false),
        };
        
        // Initialize realID FFI
        let realid_ffi = RealIdFfi::new()?;
        
        // Derive identity ID
        let identity_id = {
            let mut hasher = Sha512::new();
            hasher.update(ed25519_verifying_key.as_bytes());
            hasher.update(b"ghostchain-realid");
            let hash = hasher.finalize();
            hex::encode(&hash[..16])
        };
        
        info!("🔑 RealID Signer loaded with identity: {}", identity_id);
        
        Ok(Self {
            gcrypt_keypair,
            ed25519_signing_key,
            ed25519_verifying_key,
            identity_id,
            realid_ffi,
            use_gcrypt,
        })
    }
    
    /// Sign a message hash using gcrypt/ed25519 and realID verification
    pub fn sign(&self, message_hash: &[u8]) -> Result<Signature> {
        // Use realID for enhanced identity verification if needed
        let _realid_verification = self.realid_ffi.verify_identity(message_hash)?;
        
        if self.use_gcrypt {
            // Use gcrypt for signing
            let signature_bytes = self.gcrypt_keypair.private_key()
                .sign(message_hash)
                .map_err(|e| anyhow::anyhow!("Gcrypt signing failed: {}", e))?;
            
            Ok(Signature {
                data: signature_bytes,
                algorithm: "Gcrypt-Ed25519-RealID".to_string(),
                key_type: "Ed25519".to_string(),
            })
        } else {
            // Fallback to ed25519-dalek
            let ed25519_signature = self.ed25519_signing_key.sign(message_hash);
            
            Ok(Signature {
                data: ed25519_signature.to_bytes().to_vec(),
                algorithm: "Ed25519-RealID".to_string(),
                key_type: "Ed25519".to_string(),
            })
        }
    }
    
    /// Sign a GhostChain transaction using realID
    pub fn sign_transaction(&self, transaction: &GhostchainTransaction) -> Result<Signature> {
        let message = transaction.to_bytes();
        self.sign(&message)
    }
    
    /// Verify a signature using gcrypt/ed25519 and realID
    pub fn verify(&self, message_hash: &[u8], signature: &Signature, public_key_bytes: &[u8]) -> VerificationResult {
        match self.verify_internal(message_hash, signature, public_key_bytes) {
            Ok((valid, identity_id, trust_score)) => VerificationResult {
                valid,
                identity_id,
                trust_score,
                error: None,
            },
            Err(e) => {
                error!("🚨 Signature verification failed: {}", e);
                VerificationResult {
                    valid: false,
                    identity_id: None,
                    trust_score: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }
    
    /// Internal verification with gcrypt primitives
    fn verify_internal(
        &self, 
        message_hash: &[u8], 
        signature: &Signature, 
        public_key_bytes: &[u8]
    ) -> Result<(bool, Option<String>, Option<f64>)> {
        let is_valid = match signature.algorithm.as_str() {
            "Gcrypt-Ed25519-RealID" => {
                // Use gcrypt for verification
                let public_key = PublicKey::from_bytes(gcrypt::asymmetric::Algorithm::Ed25519, public_key_bytes)
                    .map_err(|e| anyhow::anyhow!("Invalid gcrypt public key: {}", e))?;
                
                public_key.verify(message_hash, &signature.data)
                    .map_err(|e| anyhow::anyhow!("Gcrypt verification failed: {}", e))
                    .is_ok()
            }
            "Ed25519-RealID" => {
                // Fallback to ed25519-dalek verification
                if signature.data.len() != 64 {
                    return Err(anyhow::anyhow!("Invalid Ed25519 signature length"));
                }
                let mut sig_bytes = [0u8; 64];
                sig_bytes.copy_from_slice(&signature.data);
                let ed25519_signature = Ed25519Signature::from_bytes(&sig_bytes);
                
                if public_key_bytes.len() != 32 {
                    return Err(anyhow::anyhow!("Invalid Ed25519 public key length"));
                }
                let public_key = VerifyingKey::from_bytes(public_key_bytes.try_into()?)?;
                
                public_key.verify(message_hash, &ed25519_signature).is_ok()
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported signature algorithm: {}", signature.algorithm));
            }
        };
        
        // Additional realID verification if signature is valid
        if is_valid {
            let _realid_check = self.realid_ffi.verify_identity(message_hash)?;
        }
        
        if !is_valid {
            return Ok((false, None, None));
        }
        
        // Generate identity ID from public key using gcrypt hasher
        let identity_id = {
            let mut hasher = gcrypt::hash::Hasher::new(gcrypt::hash::Algorithm::Sha512)
                .map_err(|e| anyhow::anyhow!("Hasher creation failed: {}", e))?;
            hasher.update(public_key_bytes);
            hasher.update(b"ghostchain-realid");
            let hash = hasher.finalize();
            hex::encode(&hash[..16])
        };
        
        // Calculate basic trust score (can be enhanced with reputation system)
        let trust_score = self.calculate_trust_score(&identity_id)?;
        
        Ok((true, Some(identity_id), Some(trust_score)))
    }
    
    /// Calculate trust score for an identity (basic implementation)
    fn calculate_trust_score(&self, _identity_id: &str) -> Result<f64> {
        // TODO: Implement comprehensive trust scoring based on:
        // - Transaction history
        // - Validator performance  
        // - Community reputation
        // - Stake amount
        
        // For now, provide a base trust score
        Ok(0.7) // 70% trust for verified signatures
    }
    
    /// Verify a transaction signature using realID
    pub fn verify_transaction(
        &self, 
        transaction: &GhostchainTransaction, 
        signature: &Signature, 
        public_key_bytes: &[u8]
    ) -> VerificationResult {
        let message = transaction.to_bytes();
        self.verify(&message, signature, public_key_bytes)
    }
    
    /// Get public key bytes
    pub fn get_public_key(&self) -> Vec<u8> {
        if self.use_gcrypt {
            self.gcrypt_keypair.public_key().as_bytes()
        } else {
            self.ed25519_verifying_key.as_bytes().to_vec()
        }
    }
    
    /// Get identity ID
    pub fn get_identity_id(&self) -> &str {
        &self.identity_id
    }
    
    /// Hash message using SHA-512 (compatible with Ed25519)
    pub fn hash_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        if self.use_gcrypt {
            let mut hasher = gcrypt::hash::Hasher::new(gcrypt::hash::Algorithm::Sha512)
                .map_err(|e| anyhow::anyhow!("Gcrypt hasher creation failed: {}", e))?;
            hasher.update(message);
            Ok(hasher.finalize())
        } else {
            // Fallback to sha2 crate
            use sha2::{Digest, Sha512};
            let mut hasher = Sha512::new();
            hasher.update(message);
            Ok(hasher.finalize().to_vec())
        }
    }
    
    /// Export private key bytes (use with caution)
    pub fn export_private_key(&self) -> Vec<u8> {
        if self.use_gcrypt {
            self.gcrypt_keypair.private_key().as_bytes()
        } else {
            self.ed25519_signing_key.to_bytes().to_vec()
        }
    }
}

/// Helper function to process raw transaction data for QUIC handlers
pub fn process_transaction_data(data: &[u8]) -> Result<GhostchainTransaction> {
    // Simple binary format: from(32) + to(32) + amount(8) + nonce(8) = 80 bytes
    if data.len() != 80 {
        return Err(anyhow::anyhow!("Invalid transaction data length: expected 80 bytes"));
    }
    
    let mut from = [0u8; 32];
    let mut to = [0u8; 32];
    
    from.copy_from_slice(&data[0..32]);
    to.copy_from_slice(&data[32..64]);
    
    let amount = u64::from_le_bytes(data[64..72].try_into()?);
    let nonce = u64::from_le_bytes(data[72..80].try_into()?);
    
    Ok(GhostchainTransaction {
        from,
        to,
        amount,
        nonce,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_realid_signer_creation() {
        let signer = RealIdSigner::new().unwrap();
        assert!(!signer.get_identity_id().is_empty());
        assert_eq!(signer.get_public_key().len(), 32);
    }
    
    #[test]
    fn test_transaction_signing_and_verification() {
        let signer = RealIdSigner::new().unwrap();
        
        let transaction = GhostchainTransaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1000,
            nonce: 1,
        };
        
        let signature = signer.sign_transaction(&transaction).unwrap();
        let public_key = signer.get_public_key();
        let verification = signer.verify_transaction(&transaction, &signature, &public_key);
        
        assert!(verification.valid);
        assert!(verification.identity_id.is_some());
        assert!(verification.trust_score.is_some());
    }
    
    #[test]
    fn test_raw_message_signing() {
        let signer = RealIdSigner::new().unwrap();
        let message = b"Hello, GhostChain!";
        
        let signature = signer.sign(message).unwrap();
        let public_key = signer.get_public_key();
        let verification = signer.verify(message, &signature, &public_key);
        
        assert!(verification.valid);
        assert!(signature.algorithm.contains("Ed25519"));
        assert!(signature.algorithm.contains("RealID"));
        assert_eq!(signature.data.len(), 64);
    }
}
