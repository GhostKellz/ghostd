# GCrypt Integration Guide for Ghostchain Projects

This guide provides comprehensive instructions for integrating gcrypt into your Rust and Zig based crypto projects within the Ghostchain ecosystem.

## Table of Contents

1. [Overview](#overview)
2. [Key Features for Ghostchain](#key-features-for-ghostchain)
3. [Rust Integration](#rust-integration)
4. [Zig Integration](#zig-integration)
5. [Ghostchain-Specific Patterns](#ghostchain-specific-patterns)
6. [Performance Considerations](#performance-considerations)
7. [Security Best Practices](#security-best-practices)

## Overview

GCrypt is a modern, high-performance pure Rust cryptographic library focused on Curve25519 operations. It provides constant-time implementations of:

- **Ed25519**: Digital signatures
- **X25519**: Key exchange  
- **Ristretto255**: Prime-order group operations
- **Advanced protocols**: VRFs, ring signatures, threshold crypto, bulletproofs

### Why GCrypt for Ghostchain?

- **No-std support**: Perfect for blockchain runtime environments
- **Constant-time operations**: Essential for validator nodes
- **Modern Rust 2024**: Latest safety and performance features
- **Formal verification ready**: Integration with fiat-crypto backend
- **Efficient backends**: Automatic 32/64-bit selection

## Key Features for Ghostchain

### 1. Core Primitives
- Scalar arithmetic modulo L (group order)
- Field arithmetic over GF(2^255 - 19)
- Edwards/Montgomery point operations
- Ristretto255 for protocol design

### 2. Protocol Support
- **Ed25519 signatures** for transaction signing
- **X25519 ECDH** for encrypted communication
- **VRFs** for randomness beacon
- **Ring signatures** for privacy features
- **Threshold signatures** for validator consensus
- **Bulletproofs** for range proofs

## Rust Integration

### Basic Setup

Add to your `Cargo.toml`:

```toml
[dependencies]
gcrypt = { version = "0.2", default-features = false, features = ["alloc"] }

# For full features including randomness
gcrypt = { version = "0.2", features = ["rand_core", "serde", "zeroize"] }
```

### Transaction Signing (Ed25519)

```rust
use gcrypt::{
    protocols::{Ed25519Signature, Ed25519PublicKey, Ed25519SecretKey},
    Scalar,
};

pub struct GhostchainTransaction {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub nonce: u64,
}

impl GhostchainTransaction {
    /// Sign a transaction using Ed25519
    pub fn sign(&self, secret_key: &Ed25519SecretKey) -> Ed25519Signature {
        let message = self.to_bytes();
        secret_key.sign(&message)
    }
    
    /// Verify transaction signature
    pub fn verify(&self, public_key: &Ed25519PublicKey, signature: &Ed25519Signature) -> bool {
        let message = self.to_bytes();
        public_key.verify(&message, signature).is_ok()
    }
    
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(&self.from);
        bytes.extend_from_slice(&self.to);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        bytes
    }
}
```

### Validator Key Exchange (X25519)

```rust
use gcrypt::protocols::{x25519, X25519PublicKey, X25519SecretKey};

pub struct ValidatorNode {
    node_id: [u8; 32],
    x25519_secret: X25519SecretKey,
    x25519_public: X25519PublicKey,
}

impl ValidatorNode {
    /// Create a new validator node with ephemeral keys
    pub fn new(node_id: [u8; 32]) -> Self {
        let secret = X25519SecretKey::random(&mut rand::thread_rng());
        let public = X25519PublicKey::from(&secret);
        
        Self {
            node_id,
            x25519_secret: secret,
            x25519_public: public,
        }
    }
    
    /// Establish shared secret with another validator
    pub fn establish_channel(&self, peer_public: &X25519PublicKey) -> [u8; 32] {
        x25519(self.x25519_secret.as_bytes(), peer_public.as_bytes())
    }
}
```

### VRF for Randomness Beacon

```rust
use gcrypt::protocols::{VrfProof, VrfPublicKey, VrfSecretKey};

pub struct RandomnessBeacon {
    epoch: u64,
    vrf_key: VrfSecretKey,
}

impl RandomnessBeacon {
    /// Generate verifiable random output for an epoch
    pub fn generate_randomness(&self, epoch: u64) -> (Vec<u8>, VrfProof) {
        let input = format!("ghostchain:beacon:epoch:{}", epoch);
        self.vrf_key.prove(input.as_bytes())
    }
    
    /// Verify randomness from another validator
    pub fn verify_randomness(
        public_key: &VrfPublicKey,
        epoch: u64,
        output: &[u8],
        proof: &VrfProof,
    ) -> bool {
        let input = format!("ghostchain:beacon:epoch:{}", epoch);
        public_key.verify(input.as_bytes(), output, proof).is_ok()
    }
}
```

### Ring Signatures for Privacy

```rust
use gcrypt::protocols::{RingSignature, Ed25519PublicKey, Ed25519SecretKey};

pub struct PrivateTransaction {
    pub ring_members: Vec<Ed25519PublicKey>,
    pub amount: u64,
}

impl PrivateTransaction {
    /// Create anonymous signature hiding sender among ring members
    pub fn sign_anonymous(
        &self,
        secret_key: &Ed25519SecretKey,
        my_index: usize,
    ) -> RingSignature {
        let message = self.amount.to_le_bytes();
        RingSignature::sign(
            &message,
            &self.ring_members,
            secret_key,
            my_index,
        )
    }
    
    /// Verify anonymous signature
    pub fn verify_anonymous(&self, signature: &RingSignature) -> bool {
        let message = self.amount.to_le_bytes();
        signature.verify(&message, &self.ring_members)
    }
}
```

### Threshold Signatures for Consensus

```rust
use gcrypt::protocols::{
    ThresholdSignature, ThresholdPublicKey, ThresholdSecretShare,
    threshold_keygen, threshold_sign, threshold_combine,
};

pub struct ConsensusManager {
    threshold: usize,
    total_validators: usize,
    public_key: ThresholdPublicKey,
}

impl ConsensusManager {
    /// Initialize threshold signature scheme (2/3 of validators)
    pub fn new(total_validators: usize) -> (Self, Vec<ThresholdSecretShare>) {
        let threshold = (total_validators * 2) / 3 + 1;
        let (public_key, shares) = threshold_keygen(threshold, total_validators);
        
        let manager = Self {
            threshold,
            total_validators,
            public_key,
        };
        
        (manager, shares)
    }
    
    /// Create partial signature for block
    pub fn sign_block(
        &self,
        block_hash: &[u8; 32],
        share: &ThresholdSecretShare,
    ) -> ThresholdSignature {
        threshold_sign(block_hash, share)
    }
    
    /// Combine signatures from validators
    pub fn finalize_block(
        &self,
        block_hash: &[u8; 32],
        partial_sigs: Vec<(usize, ThresholdSignature)>,
    ) -> Result<ThresholdSignature, &'static str> {
        if partial_sigs.len() < self.threshold {
            return Err("Insufficient signatures");
        }
        
        threshold_combine(&partial_sigs[..self.threshold])
    }
}
```

## Zig Integration

### Basic Setup

Create a `build.zig.zon`:

```zig
.{
    .name = "ghostchain-crypto",
    .version = "0.1.0",
    .dependencies = .{
        .gcrypt = .{
            .url = "https://github.com/CK-Technology/gcrypt/archive/v0.2.0.tar.gz",
            .hash = "...", // Use zig fetch to get the hash
        },
    },
}
```

### FFI Bindings

Create `gcrypt_bindings.zig`:

```zig
const std = @import("std");

// Ed25519 key sizes
pub const ED25519_PUBLIC_KEY_SIZE = 32;
pub const ED25519_SECRET_KEY_SIZE = 32;
pub const ED25519_SIGNATURE_SIZE = 64;

// X25519 key sizes  
pub const X25519_PUBLIC_KEY_SIZE = 32;
pub const X25519_SECRET_KEY_SIZE = 32;
pub const X25519_SHARED_SECRET_SIZE = 32;

// External C functions from gcrypt
extern "c" fn gcrypt_ed25519_keypair(
    public_key: *[ED25519_PUBLIC_KEY_SIZE]u8,
    secret_key: *[ED25519_SECRET_KEY_SIZE]u8,
) void;

extern "c" fn gcrypt_ed25519_sign(
    signature: *[ED25519_SIGNATURE_SIZE]u8,
    message: [*]const u8,
    message_len: usize,
    secret_key: *const [ED25519_SECRET_KEY_SIZE]u8,
) void;

extern "c" fn gcrypt_ed25519_verify(
    signature: *const [ED25519_SIGNATURE_SIZE]u8,
    message: [*]const u8,
    message_len: usize,
    public_key: *const [ED25519_PUBLIC_KEY_SIZE]u8,
) bool;

extern "c" fn gcrypt_x25519_keypair(
    public_key: *[X25519_PUBLIC_KEY_SIZE]u8,
    secret_key: *[X25519_SECRET_KEY_SIZE]u8,
) void;

extern "c" fn gcrypt_x25519(
    shared_secret: *[X25519_SHARED_SECRET_SIZE]u8,
    secret_key: *const [X25519_SECRET_KEY_SIZE]u8,
    peer_public: *const [X25519_PUBLIC_KEY_SIZE]u8,
) void;

// Zig-friendly wrappers
pub const Ed25519KeyPair = struct {
    public_key: [ED25519_PUBLIC_KEY_SIZE]u8,
    secret_key: [ED25519_SECRET_KEY_SIZE]u8,
    
    pub fn generate() Ed25519KeyPair {
        var keypair: Ed25519KeyPair = undefined;
        gcrypt_ed25519_keypair(&keypair.public_key, &keypair.secret_key);
        return keypair;
    }
    
    pub fn sign(self: *const Ed25519KeyPair, message: []const u8) [ED25519_SIGNATURE_SIZE]u8 {
        var signature: [ED25519_SIGNATURE_SIZE]u8 = undefined;
        gcrypt_ed25519_sign(&signature, message.ptr, message.len, &self.secret_key);
        return signature;
    }
};

pub fn ed25519_verify(
    public_key: *const [ED25519_PUBLIC_KEY_SIZE]u8,
    message: []const u8,
    signature: *const [ED25519_SIGNATURE_SIZE]u8,
) bool {
    return gcrypt_ed25519_verify(signature, message.ptr, message.len, public_key);
}
```

### Transaction Implementation

```zig
const std = @import("std");
const gcrypt = @import("gcrypt_bindings.zig");

pub const Transaction = struct {
    from: [32]u8,
    to: [32]u8,
    amount: u64,
    nonce: u64,
    signature: ?[gcrypt.ED25519_SIGNATURE_SIZE]u8 = null,
    
    pub fn sign(self: *Transaction, keypair: *const gcrypt.Ed25519KeyPair) void {
        const message = self.toBytes();
        self.signature = keypair.sign(message);
    }
    
    pub fn verify(self: *const Transaction, public_key: *const [32]u8) bool {
        if (self.signature == null) return false;
        
        const message = self.toBytes();
        return gcrypt.ed25519_verify(public_key, message, &self.signature.?);
    }
    
    fn toBytes(self: *const Transaction) [80]u8 {
        var buffer: [80]u8 = undefined;
        std.mem.copy(u8, buffer[0..32], &self.from);
        std.mem.copy(u8, buffer[32..64], &self.to);
        std.mem.writeIntLittle(u64, buffer[64..72], self.amount);
        std.mem.writeIntLittle(u64, buffer[72..80], self.nonce);
        return buffer;
    }
};
```

### Validator Communication

```zig
const std = @import("std");
const gcrypt = @import("gcrypt_bindings.zig");

pub const ValidatorChannel = struct {
    local_secret: [gcrypt.X25519_SECRET_KEY_SIZE]u8,
    local_public: [gcrypt.X25519_PUBLIC_KEY_SIZE]u8,
    peer_public: ?[gcrypt.X25519_PUBLIC_KEY_SIZE]u8 = null,
    shared_secret: ?[gcrypt.X25519_SHARED_SECRET_SIZE]u8 = null,
    
    pub fn init() ValidatorChannel {
        var channel: ValidatorChannel = undefined;
        gcrypt.gcrypt_x25519_keypair(&channel.local_public, &channel.local_secret);
        return channel;
    }
    
    pub fn establish(self: *ValidatorChannel, peer_public: [gcrypt.X25519_PUBLIC_KEY_SIZE]u8) void {
        self.peer_public = peer_public;
        var secret: [gcrypt.X25519_SHARED_SECRET_SIZE]u8 = undefined;
        gcrypt.gcrypt_x25519(&secret, &self.local_secret, &peer_public);
        self.shared_secret = secret;
    }
    
    pub fn encrypt(self: *const ValidatorChannel, plaintext: []const u8, allocator: std.mem.Allocator) ![]u8 {
        if (self.shared_secret == null) return error.ChannelNotEstablished;
        
        // Use shared_secret with ChaCha20Poly1305 or similar
        // This is a placeholder - integrate with your AEAD implementation
        const ciphertext = try allocator.alloc(u8, plaintext.len + 16); // +16 for auth tag
        // ... encryption logic ...
        return ciphertext;
    }
};
```

## Ghostchain-Specific Patterns

### 1. Deterministic Key Derivation

For hierarchical deterministic wallets:

```rust
use gcrypt::{Scalar, EdwardsPoint};
use sha2::{Sha512, Digest};

pub struct HDWallet {
    master_secret: Scalar,
}

impl HDWallet {
    /// Derive child key using BIP32-like scheme
    pub fn derive_child(&self, index: u32) -> (Scalar, EdwardsPoint) {
        let mut hasher = Sha512::new();
        hasher.update(self.master_secret.as_bytes());
        hasher.update(b"ghostchain-hd");
        hasher.update(&index.to_le_bytes());
        
        let hash = hasher.finalize();
        let child_scalar = Scalar::from_bytes_mod_order_wide(&hash);
        let child_point = EdwardsPoint::mul_base(&child_scalar);
        
        (child_scalar, child_point)
    }
}
```

### 2. Batch Verification

For efficient block validation:

```rust
use gcrypt::protocols::{Ed25519Signature, Ed25519PublicKey, batch_verify};

pub struct BlockValidator {
    pub transactions: Vec<(Transaction, Ed25519PublicKey, Ed25519Signature)>,
}

impl BlockValidator {
    /// Verify all transaction signatures in parallel
    pub fn verify_batch(&self) -> bool {
        let entries: Vec<(&[u8], &Ed25519PublicKey, &Ed25519Signature)> = 
            self.transactions.iter()
                .map(|(tx, pk, sig)| (tx.to_bytes().as_slice(), pk, sig))
                .collect();
                
        batch_verify(&entries)
    }
}
```

### 3. Zero-Knowledge Proofs

For privacy features using Bulletproofs:

```rust
use gcrypt::protocols::{RangeProof, ProofGenerators};

pub struct ConfidentialTransfer {
    commitment: RistrettoPoint,
    proof: RangeProof,
}

impl ConfidentialTransfer {
    /// Create confidential amount with range proof
    pub fn new(amount: u64, blinding: Scalar) -> Self {
        let gens = ProofGenerators::new(64); // 64-bit range
        let (commitment, proof) = RangeProof::prove_single(
            &gens,
            amount,
            &blinding,
            64,
        );
        
        Self { commitment, proof }
    }
    
    /// Verify amount is in valid range without revealing value
    pub fn verify(&self, gens: &ProofGenerators) -> bool {
        self.proof.verify_single(&gens, &self.commitment, 64).is_ok()
    }
}
```

### 4. Secure Multi-party Computation

For distributed key generation:

```rust
use gcrypt::{Scalar, EdwardsPoint, RistrettoPoint};

pub struct DKGParticipant {
    index: usize,
    secret_share: Scalar,
    commitments: Vec<RistrettoPoint>,
}

impl DKGParticipant {
    /// Generate polynomial for Shamir secret sharing
    pub fn generate_shares(
        &self,
        threshold: usize,
        participants: usize,
    ) -> Vec<(usize, Scalar)> {
        let mut coeffs = vec![self.secret_share];
        for _ in 1..threshold {
            coeffs.push(Scalar::random(&mut rand::thread_rng()));
        }
        
        (1..=participants)
            .map(|i| {
                let x = Scalar::from(i as u64);
                let share = polynomial_eval(&coeffs, &x);
                (i, share)
            })
            .collect()
    }
}

fn polynomial_eval(coeffs: &[Scalar], x: &Scalar) -> Scalar {
    coeffs.iter().rev().fold(Scalar::zero(), |acc, coeff| {
        &(&acc * x) + coeff
    })
}
```

## Performance Considerations

### 1. Backend Selection

```rust
// Force specific backend for testing
#[cfg(target_pointer_width = "32")]
use gcrypt::backend::u32_backend;

#[cfg(target_pointer_width = "64")]
use gcrypt::backend::u64_backend;

// Enable SIMD when available
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
use gcrypt::backend::simd_avx2;
```

### 2. Precomputation Tables

```toml
# Enable for validator nodes with memory available
gcrypt = { version = "0.2", features = ["precomputed-tables"] }
```

### 3. Batch Operations

```rust
// Process multiple operations together
let scalars: Vec<Scalar> = (0..100)
    .map(|_| Scalar::random(&mut rng))
    .collect();

// Batch scalar multiplication
let points: Vec<EdwardsPoint> = EdwardsPoint::batch_mul_base(&scalars);
```

## Security Best Practices

### 1. Secure Key Generation

```rust
use gcrypt::Scalar;
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct SecureKeyManager {
    secret: Scalar,
}

impl SecureKeyManager {
    pub fn generate() -> Self {
        // Always use cryptographically secure RNG
        let mut csprng = OsRng;
        Self {
            secret: Scalar::random(&mut csprng),
        }
    }
}

impl Drop for SecureKeyManager {
    fn drop(&mut self) {
        // Ensure secrets are zeroed on drop
        self.secret.zeroize();
    }
}
```

### 2. Constant-Time Operations

```rust
// All gcrypt operations are constant-time by default
// Avoid branching on secret data
use subtle::{Choice, ConditionallySelectable};

fn secure_select(a: &Scalar, b: &Scalar, choice: Choice) -> Scalar {
    Scalar::conditional_select(a, b, choice)
}
```

### 3. Side-Channel Resistance

```rust
// Enable additional security features
#[cfg(feature = "security-audit")]
use gcrypt::security::{constant_time_check, memory_fence};

pub fn critical_operation(secret: &Scalar) -> EdwardsPoint {
    // Insert memory fence to prevent speculation attacks
    memory_fence();
    
    let result = EdwardsPoint::mul_base(secret);
    
    // Verify constant-time execution in debug builds
    #[cfg(debug_assertions)]
    constant_time_check();
    
    result
}
```

## Testing and Validation

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use gcrypt::protocols::*;
    
    #[test]
    fn test_ghostchain_transaction_signing() {
        let keypair = Ed25519KeyPair::generate();
        let tx = GhostchainTransaction {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 1000,
            nonce: 1,
        };
        
        let signature = tx.sign(&keypair.secret);
        assert!(tx.verify(&keypair.public, &signature));
    }
}
```

### Integration Tests

```rust
#[test]
fn test_validator_consensus() {
    let (manager, shares) = ConsensusManager::new(5);
    let block_hash = [0x42u8; 32];
    
    // Collect signatures from 4 out of 5 validators (threshold = 4)
    let partial_sigs: Vec<_> = shares[..4].iter()
        .enumerate()
        .map(|(i, share)| (i, manager.sign_block(&block_hash, share)))
        .collect();
        
    let final_sig = manager.finalize_block(&block_hash, partial_sigs).unwrap();
    assert!(manager.public_key.verify(&block_hash, &final_sig));
}
```

## Resources

- [GCrypt Documentation](https://docs.rs/gcrypt)
- [GCrypt GitHub](https://github.com/CK-Technology/gcrypt)
- [Curve25519 Paper](https://cr.yp.to/ecdh/curve25519-20060209.pdf)
- [Ed25519 Paper](https://ed25519.cr.yp.to/ed25519-20110926.pdf)
- [Ristretto Group](https://ristretto.group)

## Support

For Ghostchain-specific integration questions:
- Open an issue with the `ghostchain` tag
- Contact the Ghostchain crypto team
- Review example implementations in the `ghostchain-examples/` directory