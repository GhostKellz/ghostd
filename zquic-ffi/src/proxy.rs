//! Wraith - QUIC Reverse Proxy implementation
//! Provides reverse proxy functionality over QUIC transport

use super::*;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Proxy configuration
#[repr(C)]
#[derive(Clone)]
pub struct ProxyConfig {
    pub max_backends: u32,
    pub health_check_interval_ms: u32,
    pub connection_timeout_ms: u32,
    pub load_balancing_algorithm: u8, // 0 = round-robin, 1 = least-connections
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            max_backends: 10,
            health_check_interval_ms: 5000,
            connection_timeout_ms: 30000,
            load_balancing_algorithm: 0, // round-robin
        }
    }
}

/// Backend server information
#[derive(Debug, Clone)]
pub struct BackendServer {
    pub address: String,
    pub weight: u32,
    pub active_connections: u32,
    pub healthy: bool,
    pub last_health_check: std::time::Instant,
}

/// Proxy context
pub struct ProxyContext {
    pub config: ProxyConfig,
    pub backends: Arc<RwLock<HashMap<String, BackendServer>>>,
    pub current_backend: Arc<Mutex<usize>>,
    pub health_check_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Opaque proxy handle
#[repr(C)]
pub struct CZQuicProxy { _private: [u8; 0] }

impl ProxyContext {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            backends: Arc::new(RwLock::new(HashMap::new())),
            current_backend: Arc::new(Mutex::new(0)),
            health_check_handle: None,
        }
    }

    pub async fn add_backend(&self, name: &str, address: &str, weight: u32) -> Result<()> {
        let backend = BackendServer {
            address: address.to_string(),
            weight,
            active_connections: 0,
            healthy: true,
            last_health_check: std::time::Instant::now(),
        };

        let mut backends = self.backends.write().await;
        backends.insert(name.to_string(), backend);
        
        info!("🔄 Added backend '{}' at {}", name, address);
        Ok(())
    }

    pub async fn get_next_backend(&self) -> Result<String> {
        let backends = self.backends.read().await;
        let healthy_backends: Vec<_> = backends
            .values()
            .filter(|b| b.healthy)
            .collect();

        if healthy_backends.is_empty() {
            return Err(anyhow!("No healthy backends available"));
        }

        match self.config.load_balancing_algorithm {
            0 => {
                // Round-robin
                let mut current = self.current_backend.lock().await;
                let backend = &healthy_backends[*current % healthy_backends.len()];
                *current += 1;
                Ok(backend.address.clone())
            }
            1 => {
                // Least connections
                let backend = healthy_backends
                    .iter()
                    .min_by_key(|b| b.active_connections)
                    .unwrap();
                Ok(backend.address.clone())
            }
            _ => Err(anyhow!("Invalid load balancing algorithm")),
        }
    }

    pub async fn start_health_checks(&mut self) {
        let backends = Arc::clone(&self.backends);
        let interval = self.config.health_check_interval_ms;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                tokio::time::Duration::from_millis(interval as u64)
            );

            loop {
                interval.tick().await;
                
                let mut backends = backends.write().await;
                for (name, backend) in backends.iter_mut() {
                    // Simple health check - in production this would be a real check
                    let now = std::time::Instant::now();
                    if now.duration_since(backend.last_health_check).as_secs() > 60 {
                        // Mark as potentially unhealthy if no recent checks
                        backend.healthy = rand::random(); // Random for demo
                    }
                    backend.last_health_check = now;
                    
                    debug!("🩺 Health check for '{}': {}", name, 
                          if backend.healthy { "healthy" } else { "unhealthy" });
                }
            }
        });

        self.health_check_handle = Some(handle);
        info!("🩺 Health check system started");
    }
}

/// Create QUIC reverse proxy
#[no_mangle]
pub extern "C" fn zquic_proxy_create(
    ctx: *mut CZQuicContext,
    config: *const ProxyConfig,
    proxy_out: *mut *mut CZQuicProxy,
) -> c_int {
    if ctx.is_null() || proxy_out.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let proxy_config = if config.is_null() {
        ProxyConfig::default()
    } else {
        unsafe { (*config).clone() }
    };

    let mut proxy_ctx = ProxyContext::new(proxy_config);
    let rt = get_runtime();
    
    // Start health checks
    rt.block_on(async {
        proxy_ctx.start_health_checks().await;
    });

    unsafe {
        *proxy_out = Box::into_raw(Box::new(proxy_ctx)) as *mut CZQuicProxy;
    }

    info!("🌀 Wraith QUIC reverse proxy created");
    ZQUIC_OK
}

/// Add backend server to proxy
#[no_mangle]
pub extern "C" fn zquic_proxy_add_backend(
    proxy: *mut CZQuicProxy,
    name: *const c_char,
    address: *const c_char,
    weight: u32,
) -> c_int {
    if proxy.is_null() || name.is_null() || address.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let name_str = match unsafe { from_c_string(name) } {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid backend name: {}", e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    let address_str = match unsafe { from_c_string(address) } {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid backend address: {}", e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    let proxy_ctx = unsafe { &*(proxy as *mut ProxyContext) };
    let rt = get_runtime();

    match rt.block_on(async {
        proxy_ctx.add_backend(&name_str, &address_str, weight).await
    }) {
        Ok(_) => ZQUIC_OK,
        Err(e) => {
            error!("Failed to add backend: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Route connection through proxy
#[no_mangle]
pub extern "C" fn zquic_proxy_route(
    proxy: *mut CZQuicProxy,
    conn: *mut CZQuicConnection,
) -> c_int {
    if proxy.is_null() || conn.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let proxy_ctx = unsafe { &*(proxy as *mut ProxyContext) };
    let conn_ref = unsafe { &*(conn as *mut ZQuicConnection) };
    let rt = get_runtime();

    match rt.block_on(async {
        // Get next backend
        let backend_addr = proxy_ctx.get_next_backend().await?;
        
        info!("🔄 Routing connection #{} to backend {}", conn_ref.id, backend_addr);
        
        // In a real implementation, this would:
        // 1. Create connection to backend
        // 2. Set up bidirectional stream forwarding
        // 3. Handle connection lifecycle
        
        // For now, just log the routing decision
        Ok::<(), anyhow::Error>(())
    }) {
        Ok(_) => ZQUIC_OK,
        Err(e) => {
            error!("Failed to route connection: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Get proxy statistics
#[no_mangle]
pub extern "C" fn zquic_proxy_get_stats(
    proxy: *mut CZQuicProxy,
    stats_out: *mut ProxyStats,
) -> c_int {
    if proxy.is_null() || stats_out.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let proxy_ctx = unsafe { &*(proxy as *mut ProxyContext) };
    let rt = get_runtime();

    let stats = rt.block_on(async {
        let backends = proxy_ctx.backends.read().await;
        let total_backends = backends.len() as u32;
        let healthy_backends = backends.values().filter(|b| b.healthy).count() as u32;
        let total_connections: u32 = backends.values().map(|b| b.active_connections).sum();

        ProxyStats {
            total_backends,
            healthy_backends,
            total_connections,
            requests_per_second: 0, // Would be calculated from metrics
        }
    });

    unsafe {
        *stats_out = stats;
    }

    ZQUIC_OK
}

/// Destroy proxy
#[no_mangle]
pub extern "C" fn zquic_proxy_destroy(proxy: *mut CZQuicProxy) -> c_int {
    if proxy.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        let proxy_ctx = Box::from_raw(proxy as *mut ProxyContext);
        
        // Cancel health check task
        if let Some(handle) = proxy_ctx.health_check_handle {
            handle.abort();
        }
    }

    info!("🗑️  Wraith proxy destroyed");
    ZQUIC_OK
}

/// Proxy statistics structure
#[repr(C)]
pub struct ProxyStats {
    pub total_backends: u32,
    pub healthy_backends: u32,
    pub total_connections: u32,
    pub requests_per_second: u32,
}