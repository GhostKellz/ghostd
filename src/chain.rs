use anyhow::Result;
use crate::state::ChainState;
use crate::vm::{VmDispatcher, VmType, ExecutionResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn, error};

/// Transaction structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub from: Vec<u8>,
    pub to: Option<Vec<u8>>,
    pub value: u64,
    pub gas_limit: u64,
    pub gas_price: u64,
    pub nonce: u64,
    pub data: Vec<u8>,
    pub vm_type: VmType,
    pub signature: Option<crate::signer::Signature>,
}

/// Block structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub number: u64,
    pub timestamp: u64,
    pub parent_hash: Vec<u8>,
    pub transactions: Vec<Transaction>,
    pub state_root: Vec<u8>,
    pub hash: Vec<u8>,
}

/// Transaction execution result
#[derive(Debug, Clone)]
pub struct TxResult {
    pub success: bool,
    pub gas_used: u64,
    pub return_data: Vec<u8>,
    pub logs: Vec<String>,
    pub error: Option<String>,
}

/// Chain manager for block and transaction processing
pub struct ChainManager {
    pub state: Arc<ChainState>,
    vm_dispatcher: VmDispatcher,
    mempool: Vec<Transaction>,
}

impl ChainManager {
    pub async fn new(state: Arc<ChainState>, mut vm_dispatcher: VmDispatcher) -> Result<Self> {
        info!("⛓️ Initializing ChainManager");
        
        Ok(Self {
            state,
            vm_dispatcher,
            mempool: Vec::new(),
        })
    }
    
    /// Process block using parseblocks dispatch
    pub async fn process_block(&mut self, block_data: &[u8]) -> Result<Vec<ExecutionResult>> {
        info!("📦 Processing block with {} bytes", block_data.len());
        
        // Use parseblocks dispatch for ZVM processing
        let results = self.vm_dispatcher.parseblocks_dispatch(block_data)?;
        
        info!("✅ Block processed with {} execution results", results.len());
        Ok(results)
    }
    
    /// Add transaction to mempool
    pub async fn add_transaction(&mut self, tx: Transaction) -> Result<()> {
        info!("📝 Adding transaction to mempool from {:?}", hex::encode(&tx.from));
        
        // Basic validation
        if tx.gas_limit == 0 {
            return Err(anyhow::anyhow!("Gas limit cannot be zero"));
        }
        
        self.mempool.push(tx);
        Ok(())
    }
    
    /// Execute a transaction
    pub async fn execute_transaction(&mut self, tx: &Transaction) -> Result<TxResult> {
        info!("🔥 Executing transaction with VM type: {:?}", tx.vm_type);
        
        // Get sender account
        let sender_account = self.state.get_account(&tx.from).await?
            .unwrap_or(crate::state::Account {
                nonce: 0,
                balance: 1000000, // Default balance for testing
                code_hash: None,
                storage_root: None,
            });
        
        // Validate nonce
        if tx.nonce != sender_account.nonce {
            return Ok(TxResult {
                success: false,
                gas_used: 0,
                return_data: vec![],
                logs: vec![],
                error: Some("Invalid nonce".to_string()),
            });
        }
        
        // Check balance
        let total_cost = tx.value + (tx.gas_limit * tx.gas_price);
        if sender_account.balance < total_cost {
            return Ok(TxResult {
                success: false,
                gas_used: 0,
                return_data: vec![],
                logs: vec![],
                error: Some("Insufficient balance".to_string()),
            });
        }
        
        // Execute based on transaction type
        let execution_result = if tx.to.is_none() {
            // Contract deployment
            self.deploy_contract(tx).await?
        } else {
            // Contract call or transfer
            self.call_contract(tx).await?
        };
        
        // Update account states
        if execution_result.success {
            self.update_account_states(tx, &execution_result).await?;
        }
        
        Ok(TxResult {
            success: execution_result.success,
            gas_used: execution_result.gas_used,
            return_data: execution_result.return_data,
            logs: execution_result.logs,
            error: execution_result.error,
        })
    }
    
    /// Deploy a new contract
    async fn deploy_contract(&mut self, tx: &Transaction) -> Result<ExecutionResult> {
        info!("🚀 Deploying contract with {} bytes of bytecode", tx.data.len());
        
        let address = self.vm_dispatcher.deploy(tx.vm_type, &tx.data)?;
        
        Ok(ExecutionResult {
            success: true,
            return_data: address,
            gas_used: 21000, // Base deployment gas
            logs: vec!["Contract deployed".to_string()],
            error: None,
        })
    }
    
    /// Call an existing contract
    async fn call_contract(&mut self, tx: &Transaction) -> Result<ExecutionResult> {
        if let Some(to_address) = &tx.to {
            info!("📞 Calling contract at {:?}", hex::encode(to_address));
            
            // Get contract code (placeholder)
            let bytecode = vec![0u8; 32]; // Placeholder bytecode
            
            self.vm_dispatcher.execute(tx.vm_type, &bytecode, &tx.data)
        } else {
            Ok(ExecutionResult {
                success: false,
                return_data: vec![],
                gas_used: 0,
                logs: vec![],
                error: Some("No target address for contract call".to_string()),
            })
        }
    }
    
    /// Update account states after successful transaction
    async fn update_account_states(&self, tx: &Transaction, result: &ExecutionResult) -> Result<()> {
        // Update sender account
        if let Some(mut sender) = self.state.get_account(&tx.from).await? {
            sender.nonce += 1;
            sender.balance -= tx.value + (result.gas_used * tx.gas_price);
            self.state.set_account(tx.from.clone(), sender).await?;
        }
        
        // Update recipient account if transfer
        if let Some(to_address) = &tx.to {
            if tx.value > 0 {
                let mut recipient = self.state.get_account(to_address).await?
                    .unwrap_or(crate::state::Account {
                        nonce: 0,
                        balance: 0,
                        code_hash: None,
                        storage_root: None,
                    });
                recipient.balance += tx.value;
                self.state.set_account(to_address.clone(), recipient).await?;
            }
        }
        
        Ok(())
    }
    
    /// Get mempool transactions
    pub fn get_mempool(&self) -> &[Transaction] {
        &self.mempool
    }
    
    /// Clear mempool
    pub fn clear_mempool(&mut self) {
        self.mempool.clear();
    }
}
