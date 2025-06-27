use anyhow::Result;
use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};
use crate::ffi::realid::{RealIdFfi, RealIdIdentity};

/// ZID (Zero-trust Identity) signer for blockchain operations
pub struct ZidSigner {
    realid_ffi: RealIdFfi,
    identity: Option<RealIdIdentity>,
}

/// Signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub r: Vec<u8>,
    pub s: Vec<u8>,
    pub v: u8,
}

/// Identity verification result
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub identity: Option<Vec<u8>>,
    pub error: Option<String>,
}

impl ZidSigner {
    pub fn new() -> Result<Self> {
        let realid_ffi = RealIdFfi::new()?;
        
        info!("🔑 ZID Signer initialized with RealID integration");
        
        Ok(Self {
            realid_ffi,
            identity: None,
        })
    }
    
    /// Initialize signer with passphrase
    pub fn init_with_passphrase(&mut self, passphrase: &str, device_bound: bool) -> Result<()> {
        debug!("🔐 Initializing ZID signer with passphrase");
        
        let identity = if device_bound {
            let device_fp = self.realid_ffi.generate_device_fingerprint()?;
            self.realid_ffi.generate_with_device(passphrase, &device_fp)?
        } else {
            self.realid_ffi.generate_from_passphrase(passphrase)?
        };
        
        info!("🆔 ZID signer initialized with QID: {}", hex::encode(&identity.qid));
        debug!("🔐 Device-bound identity: {}", identity.device_bound);
        
        self.identity = Some(identity);
        Ok(())
    }
    
    /// Get current identity QID
    pub fn get_qid(&self) -> Option<Vec<u8>> {
        self.identity.as_ref().map(|id| id.qid.clone())
    }
    
    /// Sign a message hash
    pub fn sign(&self, message_hash: &[u8]) -> Result<Signature> {
        let identity = self.identity.as_ref()
            .ok_or_else(|| anyhow::anyhow!("No identity loaded for signing"))?;
        
        debug!("✍️ Signing message with ZID identity QID: {}", hex::encode(&identity.qid));
        
        let signature_data = self.realid_ffi.sign_data(message_hash, &identity.private_key)?;
        
        if signature_data.len() >= 32 {
            Ok(Signature {
                r: signature_data[0..16].to_vec(),
                s: signature_data[16..32].to_vec(),
                v: 27, // Standard recovery ID
            })
        } else {
            Err(anyhow::anyhow!("Invalid signature length"))
        }
    }
    
    /// Verify a signature
    pub fn verify(&self, message_hash: &[u8], signature: &Signature, public_key: &[u8]) -> VerificationResult {
        // TODO: Implement actual ZID verification via realid FFI
        // Placeholder implementation - always returns valid for now
        
        VerificationResult {
            valid: true,
            identity: Some(public_key.to_vec()),
            error: None,
        }
    }
    
    /// Get public key
    pub fn get_public_key(&self) -> Result<Vec<u8>> {
        self.identity.as_ref()
            .map(|id| id.public_key.clone())
            .ok_or_else(|| anyhow::anyhow!("No identity loaded"))
    }
    
    /// Hash message for signing
    pub fn hash_message(&self, message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.finalize().to_vec()
    }
}
