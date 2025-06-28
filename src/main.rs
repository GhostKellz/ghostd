mod chain;
mod gcrypt_compat;
mod quic;
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
    
    info!("🔑 Initializing realID signer...");
    let signer = signer::RealIdSigner::new()?;
    
    info!("🧠 Initializing virtual machines...");
    let vm_manager = vm::VmManager::new()?;
    
    info!("⛓️ Initializing chain manager...");
    let chain = chain::ChainManager::new(state, vm_manager).await?;
    
    // Clone for QUIC server
    let chain_for_quic = chain.clone();
    let signer_for_quic = signer.clone();
    
    info!("📡 Starting gRPC server on port {}...", port);
    let grpc_handle = tokio::spawn(async move {
        rpc::start_server(port, chain, signer).await
    });
    
    info!("🚀 Starting GhostQuic server on port {}...", port + 1);
    let quic_addr = format!("[::]:{}", port + 1).parse()?;
    let quic_handle = tokio::spawn(async move {
        quic::start_ghostquic_server(quic_addr, chain_for_quic, signer_for_quic).await
    });
    
    // Wait for either server to complete (or fail)
    tokio::select! {
        grpc_result = grpc_handle => {
            match grpc_result? {
                Ok(_) => info!("📡 gRPC server completed"),
                Err(e) => warn!("📡 gRPC server error: {}", e),
            }
        }
        quic_result = quic_handle => {
            match quic_result? {
                Ok(_) => info!("🚀 QUIC server completed"),
                Err(e) => warn!("🚀 QUIC server error: {}", e),
            }
        }
    }
    
    info!("👻 ghostd shutdown complete");
    Ok(())
}
