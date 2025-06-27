mod chain;
mod rpc;
mod signer;
mod state;
mod vm;
mod ffi;
mod domains;

use anyhow::Result;
use std::env;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("👻 Starting ghostd - GhostChain Node Daemon");
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    let port = if args.len() > 1 {
        args[1].parse::<u16>().unwrap_or(50051)
    } else {
        50051
    };
    
    // Initialize core components
    info!("🔧 Initializing blockchain state...");
    let state = Arc::new(state::ChainState::new().await?);
    
    info!("🔑 Initializing identity signer...");
    let mut signer = signer::ZidSigner::new()?;
    
    // Initialize with RealID (placeholder passphrase for now)
    let realid_passphrase = env::var("GHOSTD_PASSPHRASE")
        .unwrap_or_else(|_| "ghostd_default_identity_passphrase".to_string());
    let device_bound = env::var("GHOSTD_DEVICE_BOUND").is_ok();
    
    info!("🆔 Loading RealID identity...");
    signer.init_with_passphrase(&realid_passphrase, device_bound)?;
    
    if let Some(qid) = signer.get_qid() {
        info!("✅ GhostD identity loaded - QID: {}", hex::encode(&qid[0..8]));
    }
    
    info!("🧠 Initializing virtual machines...");
    let mut vm_manager = vm::VmManager::new()?;
    
    // Initialize ZVM context with RealID
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    
    info!("🚀 Initializing ZVM context with RealID...");
    vm_manager.init_zvm_context(Some(&realid_passphrase), 0, current_time)?;
    
    info!("⛓️ Initializing chain manager...");
    let chain = chain::ChainManager::new(state, vm_manager).await?;
    
    info!("📡 Starting gRPC server on port {}...", port);
    rpc::start_server(port, chain, signer).await?;
    
    info!("👻 ghostd shutdown complete");
    Ok(())
}
