mod chain;
mod error;
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
    
    info!("🌐 Initializing peer manager...");
    let _peer_manager = Arc::new(quic::PeerManager::new());
    
    // Primary ZQUIC server (replaces gRPC)
    info!("🚀 Starting ZQUIC server on port {}...", port);
    let quic_addr = format!("[::]:{}", port).parse()?;
    let chain_for_zquic = chain.clone();
    let signer_for_zquic = signer.clone();
    let zquic_handle = tokio::task::spawn_blocking(move || {
        // Create dedicated runtime for ZQUIC server to avoid Send trait issues with FFI
        let rt = tokio::runtime::Runtime::new().expect("Failed to create ZQUIC runtime");
        rt.block_on(async move {
            quic::start_ghostquic_server(quic_addr, chain_for_zquic, signer_for_zquic).await
        })
    });
    
    // Legacy gRPC server (optional, for backwards compatibility)  
    info!("📡 Starting legacy gRPC server on port {}...", port + 1000);
    let chain_for_grpc = chain.clone();
    let signer_for_grpc = signer.clone();
    let grpc_handle = tokio::spawn(async move {
        rpc::start_server(port + 1000, chain_for_grpc, signer_for_grpc).await
    });
    
    info!("✅ GhostD fully operational with ZQUIC transport");
    info!("🔗 ZQUIC: [::]:{}  |  gRPC (legacy): [::]:{})", port, port + 1000);
    
    // Wait for either server to complete (or fail)
    tokio::select! {
        zquic_result = zquic_handle => {
            match zquic_result? {
                Ok(_) => info!("🚀 ZQUIC server completed"),
                Err(e) => warn!("🚀 ZQUIC server error: {}", e),
            }
        }
        grpc_result = grpc_handle => {
            match grpc_result? {
                Ok(_) => info!("📡 gRPC server completed"),
                Err(e) => warn!("📡 gRPC server error: {}", e),
            }
        }
    }
    
    info!("👻 ghostd shutdown complete");
    Ok(())
}
