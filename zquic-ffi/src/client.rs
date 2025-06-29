//! ZQUIC Client implementation
//! High-level client functionality built on top of FFI primitives

use super::*;

/// High-level ZQUIC client
pub struct ZQuicClient {
    context: ZQuicContext,
    connections: HashMap<String, ZQuicConnection>,
}

impl ZQuicClient {
    pub fn new(config: ZQuicConfig) -> Result<Self> {
        Ok(Self {
            context: ZQuicContext::new(config)?,
            connections: HashMap::new(),
        })
    }

    pub async fn connect(&mut self, addr: &str) -> Result<&ZQuicConnection> {
        if self.connections.contains_key(addr) {
            return Ok(self.connections.get(addr).unwrap());
        }

        // Create client endpoint if needed
        if self.context.endpoint.is_none() {
            let crypto_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerification))
                .with_no_client_auth();
            
            let client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?
            ));
            
            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(client_config);
            self.context.endpoint = Some(endpoint);
        }

        let endpoint = self.context.endpoint.as_ref().unwrap();
        let socket_addr: SocketAddr = addr.parse()?;
        
        let conn = endpoint
            .connect(socket_addr, "localhost")?
            .await?;

        let mut counter = self.context.connection_counter.lock().await;
        *counter += 1;
        let conn_id = *counter;

        let zquic_conn = ZQuicConnection::new(conn_id, conn);
        
        // Store in context and local map
        let mut connections = self.context.connections.write().await;
        connections.insert(conn_id, Arc::clone(&zquic_conn.inner));
        
        self.connections.insert(addr.to_string(), zquic_conn);

        info!("🔗 Connected to {} as connection #{}", addr, conn_id);
        Ok(self.connections.get(addr).unwrap())
    }

    pub async fn send_data(&self, addr: &str, data: &[u8]) -> Result<Vec<u8>> {
        let conn = self.connections.get(addr)
            .ok_or_else(|| anyhow!("No connection to {}", addr))?;

        // Open new stream
        let (mut send, mut recv) = conn.inner.open_bi().await?;

        // Send data
        send.write_all(data).await?;
        send.finish()?;

        // Read response
        let response = recv.read_to_end(1024 * 1024).await?; // 1MB limit

        info!("📡 Sent {} bytes to {}, received {} bytes", 
              data.len(), addr, response.len());
        
        Ok(response)
    }

    pub fn disconnect(&mut self, addr: &str) -> Result<()> {
        if let Some(conn) = self.connections.remove(addr) {
            conn.inner.close(0u8.into(), b"Client disconnect");
            info!("🔒 Disconnected from {}", addr);
        }
        Ok(())
    }

    pub fn disconnect_all(&mut self) {
        for (addr, conn) in self.connections.drain() {
            conn.inner.close(0u8.into(), b"Client shutdown");
            info!("🔒 Disconnected from {}", addr);
        }
    }
}

impl Drop for ZQuicClient {
    fn drop(&mut self) {
        self.disconnect_all();
    }
}

/// Example ZQUIC client application
pub async fn run_example_client(server_addr: SocketAddr) -> Result<()> {
    let config = ZQuicConfig::default();
    let mut client = ZQuicClient::new(config)?;
    
    info!("🚀 Connecting to server at {}", server_addr);
    let _conn = client.connect(&server_addr.to_string()).await?;
    
    // Send test messages
    for i in 1..=5 {
        let message = format!("Hello from client, message #{}", i);
        let response = client.send_data(&server_addr.to_string(), message.as_bytes()).await?;
        
        info!("📤 Sent: {}", message);
        info!("📥 Received: {}", String::from_utf8_lossy(&response));
        
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
    
    client.disconnect(&server_addr.to_string())?;
    info!("✅ Client example completed");
    
    Ok(())
}

// Helper struct for skipping certificate verification (dev only)
#[derive(Debug)]
struct SkipVerification;

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA1,
            rustls::SignatureScheme::ECDSA_SHA1_Legacy,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ED448,
        ]
    }
}