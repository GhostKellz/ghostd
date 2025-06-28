use anyhow::Result;
use quinn::{Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tracing::{info, warn, error};

use crate::chain::ChainManager;
use crate::signer::{RealIdSigner, VerificationResult, GhostchainTransaction};

/// QUIC protocol identifiers for different service types
pub const ALPN_WALLET_OPS: &[u8] = b"ghostchain-wallet";
pub const ALPN_VM_OPS: &[u8] = b"ghostchain-vm";
pub const ALPN_IDENTITY_OPS: &[u8] = b"ghostchain-identity";
pub const ALPN_P2P: &[u8] = b"ghostchain-p2p";

/// Message types for stream routing
#[repr(u8)]
pub enum MessageType {
    WalletTransaction = 0x01,
    WalletBalance = 0x02,
    VmExecution = 0x03,
    VmDeployment = 0x04,
    IdentityVerification = 0x05,
    P2PBlockSync = 0x06,
    P2PTxBroadcast = 0x07,
}

/// QUIC server handler for GhostChain operations
pub struct GhostQuicHandler {
    chain_manager: Arc<Mutex<ChainManager>>,
    signer: Arc<RealIdSigner>,
}

impl GhostQuicHandler {
    pub fn new(chain_manager: ChainManager, signer: RealIdSigner) -> Self {
        Self {
            chain_manager: Arc::new(Mutex::new(chain_manager)),
            signer: Arc::new(signer),
        }
    }

    /// Handle incoming QUIC connection
    pub async fn handle_connection(&self, connection: Connection) -> Result<()> {
        let remote_addr = connection.remote_address();
        info!("🔗 New QUIC connection from {}", remote_addr);

        // Handle bidirectional streams
        while let Ok((send, recv)) = connection.accept_bi().await {
            let chain_manager = self.chain_manager.clone();
            let signer = self.signer.clone();
            
            tokio::spawn(async move {
                if let Err(e) = Self::handle_stream(chain_manager, signer, send, recv).await {
                    error!("❌ Stream handling error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Handle a bidirectional stream
    async fn handle_stream(
        chain_manager: Arc<Mutex<ChainManager>>,
        signer: Arc<RealIdSigner>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        // Read message type
        let mut msg_type_buf = [0u8; 1];
        recv.read_exact(&mut msg_type_buf).await?;
        
        let response = match msg_type_buf[0] {
            0x01 => { // Wallet transaction
                let tx_data = Self::read_message(&mut recv, 1024 * 1024).await?; // 1MB max
                Self::process_wallet_transaction(&chain_manager, &signer, &tx_data).await?
            }
            0x02 => { // Balance query
                let query_data = Self::read_message(&mut recv, 256).await?; // 256B max
                Self::process_balance_query(&chain_manager, &query_data).await?
            }
            0x03 => { // VM execution
                let exec_data = Self::read_message(&mut recv, 10 * 1024 * 1024).await?; // 10MB max
                Self::process_vm_execution(&chain_manager, &exec_data).await?
            }
            0x04 => { // VM deployment
                let deploy_data = Self::read_message(&mut recv, 10 * 1024 * 1024).await?; // 10MB max
                Self::process_vm_deployment(&chain_manager, &deploy_data).await?
            }
            0x05 => { // Identity verification
                let identity_data = Self::read_message(&mut recv, 1024).await?; // 1KB max
                Self::process_identity_verification(&signer, &identity_data).await?
            }
            _ => {
                warn!("Unknown message type: {}", msg_type_buf[0]);
                return Ok(());
            }
        };

        // Send response
        send.write_all(&response).await?;
        send.finish()?;

        Ok(())
    }

    /// Read a message with size limit
    async fn read_message(recv: &mut RecvStream, max_size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; max_size];
        let bytes_read = recv.read(&mut buffer).await?.unwrap_or(0);
        buffer.truncate(bytes_read);
        Ok(buffer)
    }

    /// Process wallet transaction
    async fn process_wallet_transaction(
        chain_manager: &Arc<Mutex<ChainManager>>,
        signer: &Arc<RealIdSigner>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        use serde_json;
        
        #[derive(serde::Deserialize)]
        struct TransactionRequest {
            transaction: GhostchainTransaction,
            signature: Option<crate::signer::Signature>,
        }
        
        #[derive(serde::Serialize)]
        struct TransactionResponse {
            success: bool,
            transaction_hash: Option<String>,
            error: Option<String>,
            verification: Option<VerificationResult>,
        }
        
        // Parse transaction request
        let request: TransactionRequest = match serde_json::from_slice(data) {
            Ok(req) => req,
            Err(e) => {
                let error_response = TransactionResponse {
                    success: false,
                    transaction_hash: None,
                    error: Some(format!("Invalid transaction format: {}", e)),
                    verification: None,
                };
                return Ok(serde_json::to_vec(&error_response)?);
            }
        };
        
        // Verify transaction signature if present
        let verification = if let Some(ref signature) = request.signature {
            let tx_hash = signer.hash_message(&request.transaction.to_bytes())?;
            Some(signer.verify(&tx_hash, signature, &signer.get_public_key()))
        } else {
            None
        };
        
        // Check verification if signature was provided
        if let Some(ref verification) = verification {
            if !verification.valid {
                let error_response = TransactionResponse {
                    success: false,
                    transaction_hash: None,
                    error: Some("Transaction verification failed".to_string()),
                    verification: Some(verification.clone()),
                };
                return Ok(serde_json::to_vec(&error_response)?);
            }
        }
        
        // Calculate transaction hash
        let tx_hash = signer.hash_message(&request.transaction.to_bytes())?;
        let tx_hash_hex = hex::encode(&tx_hash);
        
        info!("✅ Processed transaction: {}", tx_hash_hex);
        
        let response = TransactionResponse {
            success: true,
            transaction_hash: Some(tx_hash_hex),
            error: None,
            verification,
        };
        
        Ok(serde_json::to_vec(&response)?)
    }

    /// Process balance query
    async fn process_balance_query(
        chain_manager: &Arc<Mutex<ChainManager>>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        #[derive(serde::Deserialize)]
        struct BalanceRequest {
            address: Vec<u8>,
        }
        
        #[derive(serde::Serialize)]
        struct BalanceResponse {
            balance: u64,
            nonce: u64,
            error: Option<String>,
        }
        
        let request: BalanceRequest = serde_json::from_slice(data)?;
        
        let chain = chain_manager.lock().await;
        match chain.state.get_account(&request.address).await {
            Ok(Some(account)) => {
                let response = BalanceResponse {
                    balance: account.balance,
                    nonce: account.nonce,
                    error: None,
                };
                Ok(serde_json::to_vec(&response)?)
            }
            Ok(None) => {
                let response = BalanceResponse {
                    balance: 0,
                    nonce: 0,
                    error: None,
                };
                Ok(serde_json::to_vec(&response)?)
            }
            Err(e) => {
                let response = BalanceResponse {
                    balance: 0,
                    nonce: 0,
                    error: Some(e.to_string()),
                };
                Ok(serde_json::to_vec(&response)?)
            }
        }
    }

    /// Process VM execution
    async fn process_vm_execution(
        _chain_manager: &Arc<Mutex<ChainManager>>,
        _data: &[u8],
    ) -> Result<Vec<u8>> {
        // TODO: Implement VM execution
        Ok(b"vm_execution_result".to_vec())
    }

    /// Process VM deployment
    async fn process_vm_deployment(
        _chain_manager: &Arc<Mutex<ChainManager>>,
        _data: &[u8],
    ) -> Result<Vec<u8>> {
        // TODO: Implement VM deployment
        Ok(b"contract_deployed".to_vec())
    }

    /// Process identity verification
    async fn process_identity_verification(
        signer: &Arc<RealIdSigner>,
        data: &[u8],
    ) -> Result<Vec<u8>> {
        #[derive(serde::Deserialize)]
        struct IdentityRequest {
            message: Vec<u8>,
            signature: crate::signer::Signature,
            public_key: Vec<u8>,
        }
        
        #[derive(serde::Serialize)]
        struct IdentityResponse {
            verified: bool,
            trust_score: Option<f64>,
            identity_id: Option<String>,
            error: Option<String>,
        }
        
        let request: IdentityRequest = match serde_json::from_slice(data) {
            Ok(req) => req,
            Err(e) => {
                let error_response = IdentityResponse {
                    verified: false,
                    trust_score: None,
                    identity_id: None,
                    error: Some(format!("Invalid request format: {}", e)),
                };
                return Ok(serde_json::to_vec(&error_response)?);
            }
        };
        
        // Hash the message
        let message_hash = signer.hash_message(&request.message)?;
        
        // Verify the signature and identity
        let verification_result = signer.verify(&message_hash, &request.signature, &request.public_key);
        
        let response = IdentityResponse {
            verified: verification_result.valid,
            trust_score: verification_result.trust_score,
            identity_id: verification_result.identity_id,
            error: verification_result.error,
        };
        
        if verification_result.valid {
            info!("✅ Identity verification successful");
        } else {
            warn!("❌ Identity verification failed");
        }
        
        Ok(serde_json::to_vec(&response)?)
    }
}

/// Start the QUIC server for GhostChain operations
pub async fn start_ghostquic_server(
    bind_addr: SocketAddr,
    chain_manager: ChainManager,
    signer: RealIdSigner,
) -> Result<()> {
    // Create self-signed certificate for development
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let key_der = cert.serialize_private_key_der();
    
    // Configure server
    use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let server_config = ServerConfig::with_single_cert(
        vec![CertificateDer::from(cert_der)],
        PrivateKeyDer::try_from(key_der).map_err(|e| anyhow::anyhow!("Key conversion error: {:?}", e))?,
    )?;
    
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    let handler = Arc::new(GhostQuicHandler::new(chain_manager, signer));
    
    info!("🚀 GhostQuic server starting on {}", bind_addr);
    info!("📡 Supporting protocols: wallet, VM, identity, P2P");
    
    // Accept connections
    while let Some(connection) = endpoint.accept().await {
        let handler = handler.clone();
        tokio::spawn(async move {
            match connection.await {
                Ok(conn) => {
                    if let Err(e) = handler.handle_connection(conn).await {
                        error!("Connection handling error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Connection failed: {}", e);
                }
            }
        });
    }
    
    Ok(())
}