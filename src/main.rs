mod chain;
mod rpc;
mod signer;
mod state;
mod vm;
mod ffi;

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
    let signer = signer::ZidSigner::new()?;
    
    info!("🧠 Initializing virtual machines...");
    let vm_manager = vm::VmManager::new()?;
    
    info!("⛓️ Initializing chain manager...");
    let chain = chain::ChainManager::new(state, vm_manager).await?;
    
    info!("📡 Starting gRPC server on port {}...", port);
    rpc::start_server(port, chain, signer).await?;
    
    info!("👻 ghostd shutdown complete");
    Ok(())
}
