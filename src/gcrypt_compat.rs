/// Gcrypt compatibility layer using ed25519-dalek as backend
/// This provides the gcrypt API interface until the actual gcrypt dependency is resolved

use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature as Ed25519Signature, Signer, Verifier};
use sha2::{Digest, Sha512};
use rand::{rngs::OsRng, RngCore};

pub mod prelude {
    pub use super::asymmetric::{KeyPair, PublicKey, PrivateKey, Algorithm};
    pub use super::hash::{Hasher, Algorithm as HashAlgorithm};
}

pub mod asymmetric {
    use super::*;
    
    #[derive(Debug, Clone)]
    pub enum Algorithm {
        Ed25519,
    }
    
    #[derive(Clone)]
    pub struct KeyPair {
        signing_key: SigningKey,
        verifying_key: VerifyingKey,
    }
    
    impl KeyPair {
        pub fn generate(algorithm: Algorithm) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    let mut secret_bytes = [0u8; 32];
                    OsRng.fill_bytes(&mut secret_bytes);
                    let signing_key = SigningKey::from_bytes(&secret_bytes);
                    let verifying_key = VerifyingKey::from(&signing_key);
                    Ok(Self {
                        signing_key,
                        verifying_key,
                    })
                }
            }
        }
        
        pub fn private_key(&self) -> PrivateKey {
            PrivateKey {
                signing_key: self.signing_key.clone(),
            }
        }
        
        pub fn public_key(&self) -> PublicKey {
            PublicKey {
                verifying_key: self.verifying_key.clone(),
            }
        }
    }
    
    impl Default for KeyPair {
        fn default() -> Self {
            // Create a placeholder keypair
            let mut secret_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut secret_bytes);
            let signing_key = SigningKey::from_bytes(&secret_bytes);
            let verifying_key = VerifyingKey::from(&signing_key);
            Self {
                signing_key,
                verifying_key,
            }
        }
    }
    
    #[derive(Clone)]
    pub struct PrivateKey {
        signing_key: SigningKey,
    }
    
    impl PrivateKey {
        pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    if bytes.len() != 32 {
                        return Err(anyhow::anyhow!("Invalid private key length for Ed25519"));
                    }
                    let signing_key = SigningKey::from_bytes(bytes.try_into()?);
                    Ok(Self { signing_key })
                }
            }
        }
        
        pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            let signature = self.signing_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        
        pub fn as_bytes(&self) -> Vec<u8> {
            self.signing_key.to_bytes().to_vec()
        }
    }
    
    #[derive(Clone)]
    pub struct PublicKey {
        verifying_key: VerifyingKey,
    }
    
    impl PublicKey {
        pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    if bytes.len() != 32 {
                        return Err(anyhow::anyhow!("Invalid public key length for Ed25519"));
                    }
                    let verifying_key = VerifyingKey::from_bytes(bytes.try_into()?)?;
                    Ok(Self { verifying_key })
                }
            }
        }
        
        pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
            if signature.len() != 64 {
                return Err(anyhow::anyhow!("Invalid signature length"));
            }
            let sig = Ed25519Signature::from_bytes(signature.try_into()?);
            self.verifying_key.verify(data, &sig)
                .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))
        }
        
        pub fn as_bytes(&self) -> Vec<u8> {
            self.verifying_key.as_bytes().to_vec()
        }
    }
}

pub mod hash {
    use super::*;
    
    #[derive(Debug, Clone)]
    pub enum Algorithm {
        Sha512,
    }
    
    pub struct Hasher {
        algorithm: Algorithm,
        hasher: Sha512,
    }
    
    impl Hasher {
        pub fn new(algorithm: Algorithm) -> Result<Self> {
            match algorithm {
                Algorithm::Sha512 => Ok(Self {
                    algorithm,
                    hasher: Sha512::new(),
                }),
            }
        }
        
        pub fn update(&mut self, data: &[u8]) {
            self.hasher.update(data);
        }
        
        pub fn finalize(self) -> Vec<u8> {
            self.hasher.finalize().to_vec()
        }
    }
}

/// Initialize the compatibility layer
pub fn init() {
    // Nothing to initialize for ed25519-dalek
}