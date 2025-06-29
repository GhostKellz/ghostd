//! ZQUIC FFI - High-Performance QUIC Transport with FFI Interface
//! 
//! This crate provides a comprehensive FFI layer for QUIC transport operations,
//! integrating GhostBridge (gRPC-over-QUIC), Wraith (Reverse Proxy), CNS/ZNS (DNS-over-QUIC),
//! and ZCrypto operations as outlined in the FFI specification.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::net::SocketAddr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::Arc;

use tokio::runtime::Runtime;
use tokio::sync::{mpsc, Mutex, RwLock};
use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};

// Re-export for Rust usage
pub mod ffi;
pub mod server;
pub mod client;
pub mod crypto;
pub mod dns;
pub mod grpc;
pub mod proxy;

pub use ffi::*;
pub use server::*;
pub use client::*;

// Re-export FFI functions directly
pub use ffi::{
    zquic_server_new, zquic_server_start, zquic_server_accept_connection, zquic_server_destroy,
    zquic_connection_create, zquic_connection_accept_stream, zquic_connection_close,
    zquic_stream_read, zquic_stream_write, zquic_stream_close,
};

/// Global runtime for async operations
static mut RUNTIME: Option<Runtime> = None;
static INIT: std::sync::Once = std::sync::Once::new();

/// Initialize the global Tokio runtime
fn get_runtime() -> &'static Runtime {
    unsafe {
        INIT.call_once(|| {
            RUNTIME = Some(Runtime::new().expect("Failed to create Tokio runtime"));
        });
        RUNTIME.as_ref().unwrap()
    }
}

/// ZQUIC Configuration structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ZQuicConfig {
    pub port: u16,
    pub max_connections: u32,
    pub connection_timeout_ms: u32,
    pub enable_ipv6: bool,
    pub tls_verify: bool,
    pub initial_max_data: u64,
    pub initial_max_streams: u32,
    pub max_packet_size: u32,
    pub enable_0rtt: bool,
    pub require_crypto_validation: bool,
}

impl Default for ZQuicConfig {
    fn default() -> Self {
        Self {
            port: 9443,
            max_connections: 1000,
            connection_timeout_ms: 30000,
            enable_ipv6: true,
            tls_verify: true,
            initial_max_data: 10 * 1024 * 1024, // 10MB
            initial_max_streams: 100,
            max_packet_size: 1472,
            enable_0rtt: false,
            require_crypto_validation: true,
        }
    }
}

/// ZQUIC Context - Main handle for QUIC operations
pub struct ZQuicContext {
    pub config: ZQuicConfig,
    pub endpoint: Option<quinn::Endpoint>,
    pub server_handle: Option<tokio::task::JoinHandle<Result<()>>>,
    pub connections: Arc<RwLock<HashMap<usize, Arc<quinn::Connection>>>>,
    pub connection_counter: Arc<Mutex<usize>>,
}

/// ZQUIC Connection wrapper
pub struct ZQuicConnection {
    pub id: usize,
    pub inner: Arc<quinn::Connection>,
    pub streams: Arc<RwLock<HashMap<usize, ZQuicStream>>>,
    pub stream_counter: Arc<Mutex<usize>>,
}

/// ZQUIC Stream wrapper
pub struct ZQuicStream {
    pub id: usize,
    pub send: Arc<Mutex<Option<quinn::SendStream>>>,
    pub recv: Arc<Mutex<Option<quinn::RecvStream>>>,
}

/// ZQUIC Server handle
pub struct ZQuicServer {
    pub context: *mut ZQuicContext,
    pub bind_addr: SocketAddr,
    pub incoming: Arc<Mutex<Option<quinn::Incoming>>>,
}

// Opaque C types
#[repr(C)]
pub struct CZQuicContext { _private: [u8; 0] }
#[repr(C)]
pub struct CZQuicServer { _private: [u8; 0] }
#[repr(C)]
pub struct CZQuicConnection { _private: [u8; 0] }
#[repr(C)]
pub struct CZQuicStream { _private: [u8; 0] }

// Error codes
pub const ZQUIC_OK: c_int = 0;
pub const ZQUIC_ERROR: c_int = -1;
pub const ZQUIC_ERROR_INVALID_PARAM: c_int = -2;
pub const ZQUIC_ERROR_CONNECTION_FAILED: c_int = -3;
pub const ZQUIC_ERROR_TIMEOUT: c_int = -4;
pub const ZQUIC_ERROR_CRYPTO: c_int = -5;

/// Convert Rust string to C string
pub fn to_c_string(s: &str) -> Result<CString> {
    CString::new(s).map_err(|e| anyhow!("Invalid C string: {}", e))
}

/// Convert C string to Rust string
pub unsafe fn from_c_string(s: *const c_char) -> Result<String> {
    if s.is_null() {
        return Err(anyhow!("Null pointer"));
    }
    let c_str = CStr::from_ptr(s);
    c_str.to_str()
        .map_err(|e| anyhow!("Invalid UTF-8: {}", e))
        .map(|s| s.to_string())
}

impl ZQuicContext {
    pub fn new(config: ZQuicConfig) -> Result<Self> {
        Ok(Self {
            config,
            endpoint: None,
            server_handle: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            connection_counter: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn create_endpoint(&mut self) -> Result<()> {
        let bind_addr = if self.config.enable_ipv6 {
            format!("[::]:{}", self.config.port)
        } else {
            format!("0.0.0.0:{}", self.config.port)
        };
        
        let addr: SocketAddr = bind_addr.parse()?;
        
        // Create self-signed certificate for development
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
        let cert_der = cert.serialize_der()?;
        let priv_key = cert.serialize_private_key_der();
        
        // Clone for second use
        let cert_der_clone = cert_der.clone();
        let priv_key_clone = priv_key.clone();
        
        // Configure TLS
        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.into()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key.into()),
            )?;
        
        // Set ALPN protocols
        tls_config.alpn_protocols = vec![
            b"ghostchain-wallet".to_vec(),
            b"ghostchain-vm".to_vec(),
            b"ghostchain-identity".to_vec(),
            b"ghostchain-p2p".to_vec(),
            b"h3".to_vec(), // HTTP/3 support
        ];
        
        // Configure QUIC transport
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(self.config.initial_max_streams.into());
        transport_config.max_concurrent_uni_streams(self.config.initial_max_streams.into());
        transport_config.max_idle_timeout(Some(
            std::time::Duration::from_millis(self.config.connection_timeout_ms as u64).try_into()?
        ));
        
        let server_config = quinn::ServerConfig::with_single_cert(
            vec![cert_der_clone.into()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(priv_key_clone.into()),
        )?;
        
        let endpoint = quinn::Endpoint::server(server_config, addr)?;
        
        info!("🚀 ZQUIC endpoint created on {}", addr);
        self.endpoint = Some(endpoint);
        
        Ok(())
    }
}

impl ZQuicConnection {
    pub fn new(id: usize, conn: quinn::Connection) -> Self {
        Self {
            id,
            inner: Arc::new(conn),
            streams: Arc::new(RwLock::new(HashMap::new())),
            stream_counter: Arc::new(Mutex::new(0)),
        }
    }
    
    pub async fn accept_stream(&self) -> Result<Option<ZQuicStream>> {
        match self.inner.accept_bi().await {
            Ok((send, recv)) => {
                let mut counter = self.stream_counter.lock().await;
                *counter += 1;
                let stream_id = *counter;
                
                let stream = ZQuicStream {
                    id: stream_id,
                    send: Arc::new(Mutex::new(Some(send))),
                    recv: Arc::new(Mutex::new(Some(recv))),
                };
                
                let mut streams = self.streams.write().await;
                streams.insert(stream_id, stream);
                
                Ok(streams.get(&stream_id).cloned())
            }
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => Ok(None),
            Err(e) => Err(anyhow!("Failed to accept stream: {}", e)),
        }
    }
}

impl Clone for ZQuicStream {
    fn clone(&self) -> Self {
        Self {
            id: self.id,
            send: Arc::clone(&self.send),
            recv: Arc::clone(&self.recv),
        }
    }
}

impl ZQuicStream {
    pub async fn read(&self, buffer: &mut [u8]) -> Result<usize> {
        let mut recv_guard = self.recv.lock().await;
        if let Some(ref mut recv) = recv_guard.as_mut() {
            match recv.read(buffer).await {
                Ok(Some(n)) => Ok(n),
                Ok(None) => Ok(0), // Stream finished
                Err(e) => Err(anyhow!("Read error: {}", e)),
            }
        } else {
            Err(anyhow!("Stream not available for reading"))
        }
    }
    
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        let mut send_guard = self.send.lock().await;
        if let Some(ref mut send) = send_guard.as_mut() {
            send.write_all(data).await
                .map_err(|e| anyhow!("Write error: {}", e))?;
            Ok(())
        } else {
            Err(anyhow!("Stream not available for writing"))
        }
    }
    
    pub async fn close(&self) -> Result<()> {
        let mut send_guard = self.send.lock().await;
        if let Some(mut send) = send_guard.take() {
            send.finish()
                .map_err(|e| anyhow!("Close error: {}", e))?;
        }
        Ok(())
    }
}

// Initialize logging
fn init_logging() {
    tracing_subscriber::fmt().init();
}

/// Initialize ZQUIC FFI library
#[no_mangle]
pub extern "C" fn zquic_init() -> c_int {
    init_logging();
    info!("🚀 ZQUIC FFI library initialized");
    ZQUIC_OK
}

/// Cleanup ZQUIC FFI library
#[no_mangle]
pub extern "C" fn zquic_cleanup() -> c_int {
    info!("🧹 ZQUIC FFI library cleanup");
    ZQUIC_OK
}