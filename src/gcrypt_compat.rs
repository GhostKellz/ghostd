/// GCrypt integration layer
/// Using gcrypt with proper Ed25519 types

use anyhow::Result;

pub mod prelude {
    pub use super::wrapper::{KeyPair, PublicKey, PrivateKey, Algorithm};
}

pub mod wrapper {
    use super::*;
    use gcrypt::Scalar;
    use ed25519_dalek::{SigningKey, VerifyingKey, Signature as Ed25519Signature, Signer, Verifier};
    
    #[derive(Debug, Clone)]
    pub enum Algorithm {
        Ed25519,
    }
    
    #[derive(Clone)]
    pub struct KeyPair {
        secret_key: SigningKey,
        public_key: VerifyingKey,
    }
    
    impl KeyPair {
        pub fn generate(algorithm: Algorithm) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    use rand::RngCore;
                    let mut secret_bytes = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
                    let secret_key = SigningKey::from_bytes(&secret_bytes);
                    let public_key = VerifyingKey::from(&secret_key);
                    Ok(Self { secret_key, public_key })
                }
            }
        }
        
        pub fn private_key(&self) -> PrivateKey {
            PrivateKey {
                secret_key: self.secret_key.clone(),
            }
        }
        
        pub fn public_key(&self) -> PublicKey {
            PublicKey {
                public_key: self.public_key.clone(),
            }
        }
    }
    
    impl Default for KeyPair {
        fn default() -> Self {
            Self::generate(Algorithm::Ed25519)
                .expect("Failed to generate default keypair")
        }
    }
    
    #[derive(Clone)]
    pub struct PrivateKey {
        secret_key: SigningKey,
    }
    
    impl PrivateKey {
        pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    if bytes.len() != 32 {
                        return Err(anyhow::anyhow!("Invalid private key length for Ed25519"));
                    }
                    let secret_key = SigningKey::from_bytes(bytes.try_into()?);
                    Ok(Self { secret_key })
                }
            }
        }
        
        pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
            let signature = self.secret_key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        
        pub fn as_bytes(&self) -> Vec<u8> {
            self.secret_key.to_bytes().to_vec()
        }
    }
    
    #[derive(Clone)]
    pub struct PublicKey {
        public_key: VerifyingKey,
    }
    
    impl PublicKey {
        pub fn from_bytes(algorithm: Algorithm, bytes: &[u8]) -> Result<Self> {
            match algorithm {
                Algorithm::Ed25519 => {
                    if bytes.len() != 32 {
                        return Err(anyhow::anyhow!("Invalid public key length for Ed25519"));
                    }
                    let public_key = VerifyingKey::from_bytes(bytes.try_into()?)
                        .map_err(|e| anyhow::anyhow!("Invalid Ed25519 public key: {}", e))?;
                    Ok(Self { public_key })
                }
            }
        }
        
        pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
            if signature.len() != 64 {
                return Err(anyhow::anyhow!("Invalid signature length"));
            }
            let sig = Ed25519Signature::from_bytes(signature.try_into()?);
            self.public_key.verify(data, &sig)
                .map_err(|e| anyhow::anyhow!("Verification failed: {}", e))
        }
        
        pub fn as_bytes(&self) -> Vec<u8> {
            self.public_key.as_bytes().to_vec()
        }
    }
}

// Hash functionality 
pub mod hash {
    use super::*;
    use sha2::{Digest, Sha512};
    
    #[derive(Debug, Clone)]
    pub enum Algorithm {
        Sha512,
    }
    
    pub struct Hasher {
        hasher: Sha512,
    }
    
    impl Hasher {
        pub fn new(algorithm: Algorithm) -> Result<Self> {
            match algorithm {
                Algorithm::Sha512 => Ok(Self {
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

/// Initialize gcrypt
pub fn init() {
    // Initialize gcrypt if needed
}