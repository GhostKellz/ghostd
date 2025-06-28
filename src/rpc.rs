use anyhow::Result;
use tonic::{transport::Server, Request, Response, Status};
use crate::chain::{ChainManager, Transaction};
use crate::signer::RealIdSigner;
use crate::vm::VmType;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, error};

// TODO: These would normally be generated from ghostd.proto
// For now, we'll define basic structures manually

#[derive(Debug)]
pub struct SubmitTransactionRequest {
    pub from: Vec<u8>,
    pub to: Option<Vec<u8>>,
    pub value: u64,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub vm_type: i32, // 0 = ZVM, 1 = EVM
}

#[derive(Debug)]
pub struct SubmitTransactionResponse {
    pub success: bool,
    pub tx_hash: Vec<u8>,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct QueryStateRequest {
    pub address: Vec<u8>,
}

#[derive(Debug)]
pub struct QueryStateResponse {
    pub balance: u64,
    pub nonce: u64,
    pub code_hash: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct DeployContractRequest {
    pub bytecode: Vec<u8>,
    pub vm_type: i32,
    pub gas_limit: u64,
    pub gas_price: u64,
}

#[derive(Debug)]
pub struct DeployContractResponse {
    pub success: bool,
    pub contract_address: Vec<u8>,
    pub tx_hash: Vec<u8>,
    pub error: Option<String>,
}

/// gRPC service implementation
pub struct GhostdService {
    chain_manager: Arc<Mutex<ChainManager>>,
    signer: Arc<RealIdSigner>,
}

impl GhostdService {
    pub fn new(chain_manager: ChainManager, signer: RealIdSigner) -> Self {
        Self {
            chain_manager: Arc::new(Mutex::new(chain_manager)),
            signer: Arc::new(signer),
        }
    }
    
    /// Submit a transaction to the blockchain
    pub async fn submit_transaction(&self, request: SubmitTransactionRequest) -> Result<SubmitTransactionResponse, Status> {
        info!("📝 Received transaction submission request");
        
        let vm_type = match request.vm_type {
            0 => VmType::Zvm,
            1 => VmType::Evm,
            _ => return Err(Status::invalid_argument("Invalid VM type")),
        };
        
        let transaction = Transaction {
            from: request.from,
            to: request.to,
            value: request.value,
            gas_limit: request.gas_limit,
            gas_price: request.gas_price,
            nonce: request.nonce,
            data: request.data,
            vm_type,
            signature: None, // TODO: Verify signature
        };
        
        // Calculate transaction hash
        let tx_hash = self.calculate_tx_hash(&transaction);
        
        let mut chain = self.chain_manager.lock().await;
        match chain.add_transaction(transaction.clone()).await {
            Ok(()) => {
                // Execute transaction immediately for now
                match chain.execute_transaction(&transaction).await {
                    Ok(result) => {
                        info!("✅ Transaction executed successfully");
                        Ok(SubmitTransactionResponse {
                            success: result.success,
                            tx_hash,
                            error: result.error,
                        })
                    }
                    Err(e) => {
                        error!("❌ Transaction execution failed: {}", e);
                        Ok(SubmitTransactionResponse {
                            success: false,
                            tx_hash,
                            error: Some(e.to_string()),
                        })
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to add transaction to mempool: {}", e);
                Err(Status::internal(format!("Failed to process transaction: {}", e)))
            }
        }
    }
    
    /// Query account state
    pub async fn query_state(&self, request: QueryStateRequest) -> Result<QueryStateResponse, Status> {
        info!("🔍 Received state query for address: {}", hex::encode(&request.address));
        
        let chain = self.chain_manager.lock().await;
        match chain.state.get_account(&request.address).await {
            Ok(Some(account)) => {
                Ok(QueryStateResponse {
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                })
            }
            Ok(None) => {
                // Return default account state
                Ok(QueryStateResponse {
                    balance: 0,
                    nonce: 0,
                    code_hash: None,
                })
            }
            Err(e) => {
                error!("❌ Failed to query state: {}", e);
                Err(Status::internal("Failed to query state"))
            }
        }
    }
    
    /// Deploy a contract
    pub async fn deploy_contract(&self, request: DeployContractRequest) -> Result<DeployContractResponse, Status> {
        info!("🚀 Received contract deployment request");
        
        let vm_type = match request.vm_type {
            0 => VmType::Zvm,
            1 => VmType::Evm,
            _ => return Err(Status::invalid_argument("Invalid VM type")),
        };
        
        let deployment_tx = Transaction {
            from: vec![0u8; 20], // Default sender for now
            to: None, // None indicates contract deployment
            value: 0,
            gas_limit: request.gas_limit,
            gas_price: request.gas_price,
            nonce: 0,
            data: request.bytecode,
            vm_type,
            signature: None,
        };
        
        let tx_hash = self.calculate_tx_hash(&deployment_tx);
        
        let mut chain = self.chain_manager.lock().await;
        match chain.execute_transaction(&deployment_tx).await {
            Ok(result) => {
                if result.success {
                    info!("✅ Contract deployed successfully");
                    Ok(DeployContractResponse {
                        success: true,
                        contract_address: result.return_data,
                        tx_hash,
                        error: None,
                    })
                } else {
                    error!("❌ Contract deployment failed");
                    Ok(DeployContractResponse {
                        success: false,
                        contract_address: vec![],
                        tx_hash,
                        error: result.error,
                    })
                }
            }
            Err(e) => {
                error!("❌ Contract deployment error: {}", e);
                Err(Status::internal("Contract deployment failed"))
            }
        }
    }
    
    /// Calculate transaction hash
    fn calculate_tx_hash(&self, tx: &Transaction) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&tx.from);
        if let Some(to) = &tx.to {
            hasher.update(to);
        }
        hasher.update(tx.value.to_le_bytes());
        hasher.update(tx.nonce.to_le_bytes());
        hasher.update(&tx.data);
        hasher.finalize().to_vec()
    }
}

/// Start the gRPC server
pub async fn start_server(port: u16, chain: ChainManager, signer: RealIdSigner) -> Result<()> {
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let service = GhostdService::new(chain, signer);
    
    info!("🚀 Starting gRPC server on {}", addr);
    
    // TODO: When proto files are properly generated, use the actual gRPC server setup
    // For now, we'll create a basic HTTP server to demonstrate the structure
    
    // This is a placeholder - normally would be:
    // Server::builder()
    //     .add_service(GhostdServiceServer::new(service))
    //     .serve(addr)
    //     .await?;
    
    info!("📡 gRPC server would be running on {}", addr);
    info!("⚠️  Note: Full gRPC implementation requires proto compilation");
    
    // Keep the server running
    tokio::signal::ctrl_c().await?;
    info!("🛑 Server shutdown requested");
    
    Ok(())
}
