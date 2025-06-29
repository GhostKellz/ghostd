//! ZQUIC Server implementation
//! High-level server functionality built on top of FFI primitives

use super::*;

/// High-level ZQUIC server
pub struct ZQuicServer {
    context: ZQuicContext,
    bind_addr: SocketAddr,
    running: Arc<Mutex<bool>>,
}

impl ZQuicServer {
    pub fn new(bind_addr: SocketAddr, config: ZQuicConfig) -> Result<Self> {
        let mut context_config = config;
        context_config.port = bind_addr.port();
        
        Ok(Self {
            context: ZQuicContext::new(context_config)?,
            bind_addr,
            running: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let mut running = self.running.lock().await;
        if *running {
            return Err(anyhow!("Server already running"));
        }

        self.context.create_endpoint().await?;
        *running = true;

        info!("🚀 ZQUIC server started on {}", self.bind_addr);
        Ok(())
    }

    pub async fn accept_connection(&mut self) -> Result<ZQuicConnection> {
        if let Some(ref endpoint) = self.context.endpoint {
            match endpoint.accept().await {
                Some(incoming) => {
                    let conn = incoming.await?;
                    
                    let mut counter = self.context.connection_counter.lock().await;
                    *counter += 1;
                    let conn_id = *counter;
                    
                    let zquic_conn = ZQuicConnection::new(conn_id, conn);
                    
                    // Store in context
                    let mut connections = self.context.connections.write().await;
                    connections.insert(conn_id, Arc::clone(&zquic_conn.inner));
                    
                    info!("🔗 Accepted connection #{}", conn_id);
                    Ok(zquic_conn)
                }
                None => Err(anyhow!("No more incoming connections")),
            }
        } else {
            Err(anyhow!("Server endpoint not created"))
        }
    }

    pub async fn stop(&mut self) -> Result<()> {
        let mut running = self.running.lock().await;
        if !*running {
            return Ok(());
        }

        *running = false;
        
        // Close all connections
        let connections = self.context.connections.read().await;
        for conn in connections.values() {
            conn.close(0u8.into(), b"Server shutdown");
        }

        info!("🛑 ZQUIC server stopped");
        Ok(())
    }

    pub async fn is_running(&self) -> bool {
        *self.running.lock().await
    }
}

/// Example ZQUIC server application
pub async fn run_example_server(bind_addr: SocketAddr) -> Result<()> {
    let config = ZQuicConfig::default();
    let mut server = ZQuicServer::new(bind_addr, config)?;
    
    server.start().await?;
    
    info!("🌟 Example server running on {}", bind_addr);
    info!("Press Ctrl+C to stop...");
    
    // Simple connection handling loop
    loop {
        tokio::select! {
            conn_result = server.accept_connection() => {
                match conn_result {
                    Ok(conn) => {
                        info!("📡 New connection: #{}", conn.id);
                        
                        // Spawn task to handle connection
                        tokio::spawn(async move {
                            handle_connection(conn).await
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("🛑 Shutdown signal received");
                break;
            }
        }
    }
    
    server.stop().await?;
    Ok(())
}

/// Handle individual connection
async fn handle_connection(conn: ZQuicConnection) -> Result<()> {
    info!("🔧 Handling connection #{}", conn.id);
    
    loop {
        match conn.accept_stream().await {
            Ok(Some(stream)) => {
                info!("📡 New stream #{} on connection #{}", stream.id, conn.id);
                
                // Spawn task to handle stream
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(stream).await {
                        error!("Stream handling error: {}", e);
                    }
                });
            }
            Ok(None) => {
                info!("🔒 Connection #{} closed by peer", conn.id);
                break;
            }
            Err(e) => {
                error!("Error accepting stream: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

/// Handle individual stream
async fn handle_stream(stream: ZQuicStream) -> Result<()> {
    info!("🔧 Handling stream #{}", stream.id);
    
    let mut buffer = vec![0u8; 4096];
    
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                info!("📪 Stream #{} ended (EOF)", stream.id);
                break;
            }
            Ok(n) => {
                let data = &buffer[..n];
                info!("📥 Received {} bytes on stream #{}", n, stream.id);
                
                // Echo the data back
                stream.write(data).await?;
                info!("📤 Echoed {} bytes on stream #{}", n, stream.id);
            }
            Err(e) => {
                error!("Stream read error: {}", e);
                break;
            }
        }
    }
    
    stream.close().await?;
    info!("🔒 Stream #{} closed", stream.id);
    Ok(())
}