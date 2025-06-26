use anyhow::Result;
use sled::Db;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Account state structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub nonce: u64,
    pub balance: u64,
    pub code_hash: Option<Vec<u8>>,
    pub storage_root: Option<Vec<u8>>,
}

/// Block state management
#[derive(Debug, Clone)]
pub struct ChainState {
    db: Arc<Db>,
    current_block: Arc<RwLock<u64>>,
    accounts: Arc<RwLock<std::collections::HashMap<Vec<u8>, Account>>>,
}

impl ChainState {
    pub async fn new() -> Result<Self> {
        let db = sled::open("./ghostd_data")?;
        info!("📦 Opened Sled database at ./ghostd_data");
        
        let current_block = Arc::new(RwLock::new(0));
        let accounts = Arc::new(RwLock::new(std::collections::HashMap::new()));
        
        Ok(Self {
            db: Arc::new(db),
            current_block,
            accounts,
        })
    }
    
    /// Get account by address
    pub async fn get_account(&self, address: &[u8]) -> Result<Option<Account>> {
        let accounts = self.accounts.read().await;
        Ok(accounts.get(address).cloned())
    }
    
    /// Set account state
    pub async fn set_account(&self, address: Vec<u8>, account: Account) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        accounts.insert(address, account);
        Ok(())
    }
    
    /// Get current block number
    pub async fn get_block_number(&self) -> u64 {
        *self.current_block.read().await
    }
    
    /// Increment block number
    pub async fn increment_block(&self) -> Result<u64> {
        let mut block = self.current_block.write().await;
        *block += 1;
        Ok(*block)
    }
    
    /// Store data in persistent storage
    pub fn store(&self, key: &[u8], value: &[u8]) -> Result<()> {
        self.db.insert(key, value)?;
        Ok(())
    }
    
    /// Retrieve data from persistent storage
    pub fn retrieve(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.db.get(key)?.map(|v| v.to_vec()))
    }
}
