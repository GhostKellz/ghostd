use anyhow::Result;
use revm::{
    primitives::{Address, Bytecode, Bytes, TransactTo, TxEnv, U256},
    Database, DatabaseCommit, Evm, EvmBuilder,
};
use std::collections::HashMap;
use crate::vm::{ExecutionResult, VmRuntime};
use tracing::{info, warn, error};

/// Simple in-memory database for RVM/REVM
#[derive(Debug, Default, Clone)]
pub struct MemoryDb {
    accounts: HashMap<Address, AccountInfo>,
    storage: HashMap<(Address, U256), U256>,
    block_hashes: HashMap<U256, [u8; 32]>,
}

#[derive(Debug, Default, Clone)]
pub struct AccountInfo {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: [u8; 32],
    pub code: Bytecode,
}

impl Database for MemoryDb {
    type Error = std::convert::Infallible;
    
    fn basic(&mut self, address: Address) -> Result<Option<revm::primitives::AccountInfo>, Self::Error> {
        let account = self.accounts.get(&address).cloned().unwrap_or_default();
        Ok(Some(revm::primitives::AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash.into(),
            code: Some(account.code),
        }))
    }
    
    fn code_by_hash(&mut self, _code_hash: revm::primitives::B256) -> Result<Bytecode, Self::Error> {
        Ok(Bytecode::default())
    }
    
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self.storage.get(&(address, index)).copied().unwrap_or_default())
    }
    
    fn block_hash(&mut self, number: u64) -> Result<revm::primitives::B256, Self::Error> {
        Ok(self.block_hashes.get(&U256::from(number)).copied().unwrap_or_default().into())
    }
}

impl DatabaseCommit for MemoryDb {
    fn commit(&mut self, changes: HashMap<Address, revm::primitives::Account>) {
        for (address, account) in changes {
            let account_info = AccountInfo {
                balance: account.info.balance,
                nonce: account.info.nonce,
                code_hash: account.info.code_hash.0,
                code: account.info.code.unwrap_or_default(),
            };
            self.accounts.insert(address, account_info);
            
            for (key, value) in account.storage {
                self.storage.insert((address, key), value.present_value);
            }
        }
    }
}

/// RVM (Rust Virtual Machine) runtime using REVM for EVM compatibility
#[derive(Clone)]
pub struct RvmRuntime {
    db: MemoryDb,
    gas_limit: u64,
}

impl RvmRuntime {
    pub fn new() -> Result<Self> {
        info!("🦀 RVM Runtime initialized with REVM engine");
        
        Ok(Self {
            db: MemoryDb::default(),
            gas_limit: 1_000_000, // Default gas limit
        })
    }
}

impl VmRuntime for RvmRuntime {
    fn execute(&mut self, bytecode: &[u8], input: &[u8]) -> Result<ExecutionResult> {
        info!("🔥 Executing RVM/EVM contract with {} bytes input", input.len());
        
        if bytecode.is_empty() {
            return Ok(ExecutionResult {
                success: false,
                return_data: vec![],
                gas_used: 0,
                logs: vec![],
                error: Some("Empty bytecode".to_string()),
            });
        }
        
        // Create a fresh database for this execution
        let mut db = MemoryDb::default();
        
        // Add contract code to the database
        let contract_address = Address::from([0x1; 20]);
        db.accounts.insert(
            contract_address,
            AccountInfo {
                balance: U256::ZERO,
                nonce: 0,
                code_hash: [0; 32],
                code: Bytecode::new_raw(Bytes::from(bytecode.to_vec())),
            },
        );
        
        // Create EVM with the database
        let mut evm = EvmBuilder::default()
            .with_db(db)
            .build();
        
        // Set up transaction environment
        evm.context.evm.inner.env.tx.caller = Address::ZERO;
        evm.context.evm.inner.env.tx.gas_limit = self.gas_limit;
        evm.context.evm.inner.env.tx.gas_price = U256::from(1);
        evm.context.evm.inner.env.tx.transact_to = TransactTo::Call(contract_address);
        evm.context.evm.inner.env.tx.value = U256::ZERO;
        evm.context.evm.inner.env.tx.data = Bytes::from(input.to_vec());
        evm.context.evm.inner.env.tx.nonce = Some(0);
        evm.context.evm.inner.env.tx.chain_id = Some(1);
        
        // Execute transaction
        match evm.transact_commit() {
            Ok(result) => {
                let success = result.is_success();
                let return_data = result.output().unwrap_or_default().to_vec();
                let gas_used = result.gas_used();
                
                info!("✅ RVM execution completed, success: {}, gas used: {}", success, gas_used);
                
                Ok(ExecutionResult {
                    success,
                    return_data,
                    gas_used,
                    logs: vec!["RVM execution completed".to_string()],
                    error: if success { None } else { Some("EVM execution reverted".to_string()) },
                })
            }
            Err(e) => {
                error!("❌ RVM execution failed: {:?}", e);
                Ok(ExecutionResult {
                    success: false,
                    return_data: vec![],
                    gas_used: self.gas_limit, // Use full gas on error
                    logs: vec![],
                    error: Some(format!("EVM execution error: {:?}", e)),
                })
            }
        }
    }
    
    fn deploy(&mut self, bytecode: &[u8]) -> Result<Vec<u8>> {
        info!("🚀 Deploying RVM/EVM contract with {} bytes", bytecode.len());
        
        if bytecode.is_empty() {
            return Err(anyhow::anyhow!("Empty bytecode for deployment"));
        }
        
        // Create a fresh database for deployment
        let db = MemoryDb::default();
        
        // Create EVM for deployment
        let mut evm = EvmBuilder::default()
            .with_db(db)
            .build();
        
        // Set up deployment transaction
        evm.context.evm.inner.env.tx.caller = Address::ZERO;
        evm.context.evm.inner.env.tx.gas_limit = self.gas_limit;
        evm.context.evm.inner.env.tx.gas_price = U256::from(1);
        evm.context.evm.inner.env.tx.transact_to = TransactTo::Create;
        evm.context.evm.inner.env.tx.value = U256::ZERO;
        evm.context.evm.inner.env.tx.data = Bytes::from(bytecode.to_vec());
        evm.context.evm.inner.env.tx.nonce = Some(0);
        evm.context.evm.inner.env.tx.chain_id = Some(1);
        
        // Execute deployment
        match evm.transact_commit() {
            Ok(result) => {
                if result.is_success() {
                    // Generate contract address (CREATE opcode logic)
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(bytecode);
                    let address = hasher.finalize()[0..20].to_vec();
                    
                    info!("✅ RVM contract deployed at address: {}", hex::encode(&address));
                    Ok(address)
                } else {
                    error!("❌ RVM contract deployment failed");
                    Err(anyhow::anyhow!("Contract deployment reverted"))
                }
            }
            Err(e) => {
                error!("❌ RVM deployment error: {:?}", e);
                Err(anyhow::anyhow!("Deployment execution failed: {:?}", e))
            }
        }
    }
    
    fn get_gas_limit(&self) -> u64 {
        self.gas_limit
    }
    
    fn set_gas_limit(&mut self, limit: u64) {
        self.gas_limit = limit;
        info!("⛽ RVM gas limit set to {}", limit);
    }
}
