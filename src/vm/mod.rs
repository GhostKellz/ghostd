pub mod zvm;
pub mod rvm;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// VM execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub success: bool,
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub logs: Vec<String>,
    pub error: Option<String>,
}

/// VM type enumeration based on VIRTUALMACHINE.md
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VmType {
    /// Zig-based WASM runtime for GhostChain native contracts
    Zvm,
    /// Rust-based EVM runtime for Ethereum compatibility
    Evm,
}

/// Unified VM runtime trait for dispatch
pub trait VmRuntime {
    fn execute(&mut self, bytecode: &[u8], input: &[u8]) -> Result<ExecutionResult>;
    fn deploy(&mut self, bytecode: &[u8]) -> Result<Vec<u8>>;
    fn get_gas_limit(&self) -> u64;
    fn set_gas_limit(&mut self, limit: u64);
}

/// VM dispatcher - routes execution to correct VM based on type
#[derive(Clone)]
pub struct VmDispatcher {
    zvm: zvm::ZvmRuntime,
    rvm: rvm::RvmRuntime,
}

impl VmDispatcher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            zvm: zvm::ZvmRuntime::new()?,
            rvm: rvm::RvmRuntime::new()?,
        })
    }

    /// Execute contract based on VM type
    pub fn execute(&mut self, vm_type: VmType, bytecode: &[u8], input: &[u8]) -> Result<ExecutionResult> {
        match vm_type {
            VmType::Zvm => self.zvm.execute(bytecode, input),
            VmType::Evm => self.rvm.execute(bytecode, input),
        }
    }

    /// Deploy contract based on VM type
    pub fn deploy(&mut self, vm_type: VmType, bytecode: &[u8]) -> Result<Vec<u8>> {
        match vm_type {
            VmType::Zvm => self.zvm.deploy(bytecode),
            VmType::Evm => self.rvm.deploy(bytecode),
        }
    }
}

/// VM Manager alias for main.rs compatibility
pub type VmManager = VmDispatcher;
