//! Comprehensive error handling for GhostD
//! Provides structured error types for all components

use thiserror::Error;
use std::fmt;

/// Main error type for GhostD operations
#[derive(Error, Debug)]
pub enum GhostdError {
    #[error("QUIC transport error: {0}")]
    QuicError(#[from] QuicError),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] CryptoError),
    
    #[error("Validation error: {0}")]
    ValidationError(#[from] ValidationError),
    
    #[error("Chain state error: {0}")]
    ChainError(#[from] ChainError),
    
    #[error("VM execution error: {0}")]
    VmError(#[from] VmError),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Generic error: {0}")]
    AnyhowError(#[from] anyhow::Error),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// QUIC transport specific errors
#[derive(Error, Debug)]
pub enum QuicError {
    #[error("FFI operation failed: {0}")]
    FfiError(String),
    
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Stream error: {0}")]
    StreamError(String),
    
    #[error("Server startup failed: {0}")]
    ServerStartupFailed(String),
    
    #[error("Invalid message format: {0}")]
    InvalidMessage(String),
    
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
}

/// Cryptographic operation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),
    
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Verification failed: {0}")]
    VerificationFailed(String),
    
    #[error("Hash computation failed: {0}")]
    HashFailed(String),
    
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),
}

/// Validation errors for input data
#[derive(Error, Debug)]
pub enum ValidationError {
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),
    
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),
    
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),
    
    #[error("Missing required field: {0}")]
    MissingField(String),
    
    #[error("Field too large: {field} (max: {max}, got: {actual})")]
    FieldTooLarge { field: String, max: usize, actual: usize },
    
    #[error("Field too small: {field} (min: {min}, got: {actual})")]
    FieldTooSmall { field: String, min: usize, actual: usize },
    
    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },
    
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
}

/// Chain state and blockchain errors
#[derive(Error, Debug)]
pub enum ChainError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Block not found: {0}")]
    BlockNotFound(u64),
    
    #[error("Transaction not found: {0}")]
    TransactionNotFound(String),
    
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    
    #[error("Invalid block: {0}")]
    InvalidBlock(String),
    
    #[error("Chain synchronization error: {0}")]
    SyncError(String),
    
    #[error("Consensus error: {0}")]
    ConsensusError(String),
}

/// Virtual machine execution errors
#[derive(Error, Debug)]
pub enum VmError {
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    
    #[error("Out of gas: limit {limit}, used {used}")]
    OutOfGas { limit: u64, used: u64 },
    
    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),
    
    #[error("Contract not found: {0}")]
    ContractNotFound(String),
    
    #[error("Deployment failed: {0}")]
    DeploymentFailed(String),
    
    #[error("Runtime error: {0}")]
    RuntimeError(String),
}

/// Result type alias for GhostD operations
pub type Result<T> = std::result::Result<T, GhostdError>;

/// Trait for converting error codes to structured errors
pub trait FromErrorCode {
    fn from_code(code: i32, context: &str) -> GhostdError;
}

impl FromErrorCode for GhostdError {
    fn from_code(code: i32, context: &str) -> GhostdError {
        match code {
            -1 => GhostdError::QuicError(QuicError::FfiError(format!("FFI error in {}", context))),
            -2 => GhostdError::ValidationError(ValidationError::MissingField(context.to_string())),
            -3 => GhostdError::QuicError(QuicError::ConnectionFailed(context.to_string())),
            -4 => GhostdError::QuicError(QuicError::Timeout(context.to_string())),
            -5 => GhostdError::CryptoError(CryptoError::SigningFailed(context.to_string())),
            _ => GhostdError::InternalError(format!("Unknown error code {} in {}", code, context)),
        }
    }
}

/// Helper macros for error handling
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr) => {
        if !($cond) {
            return Err($err.into());
        }
    };
}

#[macro_export]
macro_rules! bail {
    ($err:expr) => {
        return Err($err.into());
    };
}

/// Validation helpers
pub struct Validator;

impl Validator {
    /// Validate transaction data
    pub fn validate_transaction(tx: &crate::signer::GhostchainTransaction) -> Result<()> {
        // Validate address format (32 bytes for GhostChain)
        if tx.to.len() != 32 {
            bail!(ValidationError::InvalidAddress(format!(
                "Invalid 'to' address length: expected 32 bytes, got {}", tx.to.len()
            )));
        }
        
        if tx.from.len() != 32 {
            bail!(ValidationError::InvalidAddress(format!(
                "Invalid 'from' address length: expected 32 bytes, got {}", tx.from.len()
            )));
        }
        
        // Validate amount (can be 0 for pure data transactions)
        if tx.amount == 0 {
            // For zero-value transactions, just log a warning
            // Note: tracing is not imported here, so we skip the log
        }
        
        // Validate nonce (should be sequential)
        if tx.nonce == 0 {
            bail!(ValidationError::InvalidTransaction(
                "Transaction nonce cannot be zero".to_string()
            ));
        }
        
        Ok(())
    }
    
    /// Validate signature format
    pub fn validate_signature(signature: &crate::signer::Signature) -> Result<()> {
        if signature.data.len() != 64 {
            bail!(CryptoError::InvalidSignatureFormat(format!(
                "Expected 64 bytes signature data, got {}", signature.data.len()
            )));
        }
        
        // Validate signature algorithm string
        match signature.algorithm.as_str() {
            "Ed25519-RealID" | "Gcrypt-Ed25519" => {
                // Ed25519 signatures are always 64 bytes, which we validated above
            }
            _ => {
                bail!(CryptoError::InvalidSignatureFormat(format!(
                    "Unknown signature algorithm: {}", signature.algorithm
                )));
            }
        }
        
        Ok(())
    }
    
    /// Validate account balance for transaction
    pub fn validate_balance(available: u64, required: u64) -> Result<()> {
        if available < required {
            bail!(ValidationError::InsufficientBalance {
                required,
                available,
            });
        }
        Ok(())
    }
    
    /// Validate message size limits
    pub fn validate_message_size(data: &[u8], max_size: usize, context: &str) -> Result<()> {
        if data.len() > max_size {
            bail!(ValidationError::FieldTooLarge {
                field: context.to_string(),
                max: max_size,
                actual: data.len(),
            });
        }
        Ok(())
    }
    
    /// Validate network address format
    pub fn validate_network_address(addr: &str) -> Result<std::net::SocketAddr> {
        addr.parse().map_err(|e| {
            ValidationError::InvalidAddress(format!("Invalid network address '{}': {}", addr, e)).into()
        })
    }
}

/// Security audit helpers with comprehensive threat detection
pub struct SecurityAudit;

impl SecurityAudit {
    /// Check for potential security issues in transaction data
    pub fn audit_transaction(tx: &crate::signer::GhostchainTransaction) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check for suspiciously large amounts
        if tx.amount > 1_000_000_000_000 { // 1 trillion tokens
            warnings.push("Extremely large transaction amount detected".to_string());
        }
        
        // Check for zero-value transactions (potential spam)
        if tx.amount == 0 {
            warnings.push("Zero-value transaction - potential spam or data transaction".to_string());
        }
        
        // Check for suspicious nonce patterns
        if tx.nonce > 1_000_000 {
            warnings.push("Very high nonce value detected - check for replay attacks".to_string());
        }
        
        warnings
    }
    
    /// Audit FFI calls for safety
    pub fn audit_ffi_call(function_name: &str, params: &[&str]) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check for potentially dangerous FFI operations
        if function_name.contains("destroy") || function_name.contains("free") {
            warnings.push(format!("Cleanup function called: {} - ensure proper lifecycle", function_name));
        }
        
        // Check for null pointer risks
        for (i, param) in params.iter().enumerate() {
            if param.contains("null") {
                warnings.push(format!("Null pointer in parameter {} of {}", i, function_name));
            }
        }
        
        warnings
    }
    
    /// Audit network connections for security threats
    pub fn audit_connection(remote_addr: &str, local_addr: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check for suspicious IP patterns
        if remote_addr.starts_with("127.") && !local_addr.starts_with("127.") {
            warnings.push("Potential localhost spoofing attempt".to_string());
        }
        
        // Check for private network abuse
        if remote_addr.starts_with("10.") || remote_addr.starts_with("192.168.") {
            warnings.push("Connection from private network range".to_string());
        }
        
        // Check for common attack ports
        if remote_addr.contains(":22") || remote_addr.contains(":23") || remote_addr.contains(":3389") {
            warnings.push("Connection from suspicious port (SSH/Telnet/RDP)".to_string());
        }
        
        warnings
    }
    
    /// Audit data payloads for malicious content
    pub fn audit_payload(data: &[u8], context: &str) -> Vec<String> {
        let mut warnings = Vec::new();
        
        // Check for oversized payloads
        if data.len() > 1024 * 1024 { // 1MB
            warnings.push(format!("Large payload in {}: {} bytes", context, data.len()));
        }
        
        // Check for suspicious patterns (common exploit signatures)
        let suspicious_patterns: &[&[u8]] = &[
            b"\\x90\\x90\\x90\\x90", // NOP sled
            b"../../../",          // Path traversal
            b"<script>",           // XSS attempt
            b"' OR 1=1",          // SQL injection
            b"\\x00\\x00\\x00\\x00", // Null bytes
        ];
        
        for pattern in suspicious_patterns {
            if data.windows(pattern.len()).any(|window| window == *pattern) {
                warnings.push(format!("Suspicious pattern detected in {}", context));
                break;
            }
        }
        
        // Check for excessive repeated bytes (potential DoS)
        if data.len() > 100 {
            let first_byte = data[0];
            if data.iter().take(100).all(|&b| b == first_byte) {
                warnings.push(format!("Potential DoS pattern in {}: repeated bytes", context));
            }
        }
        
        warnings
    }
    
    /// Rate limiting audit for preventing abuse
    pub fn audit_rate_limit(source: &str, requests_count: u32, time_window_seconds: u64) -> Vec<String> {
        let mut warnings = Vec::new();
        
        let requests_per_second = requests_count as f64 / time_window_seconds as f64;
        
        // Check for potential DDoS
        if requests_per_second > 100.0 {
            warnings.push(format!("High request rate from {}: {:.2} req/s", source, requests_per_second));
        }
        
        // Check for sustained high load
        if requests_count > 1000 && time_window_seconds < 60 {
            warnings.push(format!("Burst traffic from {}: {} requests in {}s", source, requests_count, time_window_seconds));
        }
        
        warnings
    }
}

/// Error recovery utilities
pub struct ErrorRecovery;

impl ErrorRecovery {
    /// Attempt to recover from QUIC connection errors
    pub fn recover_quic_connection(error: &QuicError) -> Option<String> {
        match error {
            QuicError::ConnectionFailed(msg) if msg.contains("timeout") => {
                Some("Retry with exponential backoff".to_string())
            }
            QuicError::StreamError(msg) if msg.contains("reset") => {
                Some("Reconnect and retry operation".to_string())
            }
            QuicError::FfiError(msg) if msg.contains("invalid") => {
                Some("Validate input parameters and retry".to_string())
            }
            _ => None,
        }
    }
    
    /// Attempt to recover from crypto errors
    pub fn recover_crypto_error(error: &CryptoError) -> Option<String> {
        match error {
            CryptoError::KeyGenerationFailed(_) => {
                Some("Regenerate keys with fresh entropy".to_string())
            }
            CryptoError::VerificationFailed(_) => {
                Some("Check signature and public key format".to_string())
            }
            CryptoError::InvalidKeyFormat(_) => {
                Some("Verify key encoding and try alternative format".to_string())
            }
            _ => None,
        }
    }
}

