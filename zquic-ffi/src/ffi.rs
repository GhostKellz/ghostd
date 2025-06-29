//! C FFI interface for ZQUIC operations
//! Provides C-compatible functions for all ZQUIC functionality

use super::*;
use std::slice;

/// FFI Safety helpers for parameter validation and error handling
struct FfiSafety;

impl FfiSafety {
    /// Validate pointer is not null
    fn validate_ptr<T>(ptr: *const T, name: &str) -> Result<()> {
        if ptr.is_null() {
            Err(anyhow!("Null pointer for {}", name))
        } else {
            Ok(())
        }
    }
    
    /// Validate mutable pointer is not null
    fn validate_mut_ptr<T>(ptr: *mut T, name: &str) -> Result<()> {
        if ptr.is_null() {
            Err(anyhow!("Null mutable pointer for {}", name))
        } else {
            Ok(())
        }
    }
    
    /// Validate buffer with size
    fn validate_buffer(ptr: *const u8, len: usize, name: &str) -> Result<()> {
        if ptr.is_null() && len > 0 {
            Err(anyhow!("Null buffer pointer for {} with non-zero length {}", name, len))
        } else if len > 16 * 1024 * 1024 { // 16MB limit
            Err(anyhow!("Buffer {} too large: {} bytes (max 16MB)", name, len))
        } else {
            Ok(())
        }
    }
    
    /// Validate output buffer
    fn validate_output_buffer(ptr: *mut u8, len: usize, name: &str) -> Result<()> {
        if ptr.is_null() && len > 0 {
            Err(anyhow!("Null output buffer pointer for {} with non-zero length {}", name, len))
        } else if len > 16 * 1024 * 1024 { // 16MB limit
            Err(anyhow!("Output buffer {} too large: {} bytes (max 16MB)", name, len))
        } else {
            Ok(())
        }
    }
    
    /// Convert error to C error code
    fn error_to_code(error: &anyhow::Error) -> c_int {
        let error_str = error.to_string().to_lowercase();
        
        if error_str.contains("null pointer") {
            ZQUIC_ERROR_INVALID_PARAM
        } else if error_str.contains("timeout") {
            ZQUIC_ERROR_TIMEOUT
        } else if error_str.contains("connection") {
            ZQUIC_ERROR_CONNECTION_FAILED
        } else if error_str.contains("crypto") {
            ZQUIC_ERROR_CRYPTO
        } else {
            ZQUIC_ERROR
        }
    }
}

// ============================================================================
// CORE CONTEXT MANAGEMENT
// ============================================================================

/// Create new ZQUIC context with configuration
#[no_mangle]
pub extern "C" fn zquic_context_new(
    config: *const ZQuicConfig,
    ctx_out: *mut *mut CZQuicContext,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_ptr(config, "config") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(ctx_out, "ctx_out") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let config = unsafe { (*config).clone() };
    
    match ZQuicContext::new(config) {
        Ok(ctx) => {
            let boxed_ctx = Box::new(ctx);
            unsafe {
                *ctx_out = Box::into_raw(boxed_ctx) as *mut CZQuicContext;
            }
            ZQUIC_OK
        }
        Err(e) => {
            error!("Failed to create ZQUIC context: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Destroy ZQUIC context
#[no_mangle]
pub extern "C" fn zquic_context_destroy(ctx: *mut CZQuicContext) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(ctx, "ctx") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        let _ = Box::from_raw(ctx as *mut ZQuicContext);
    }
    
    debug!("ZQUIC context destroyed");
    ZQUIC_OK
}

// ============================================================================
// SERVER OPERATIONS
// ============================================================================

/// Create new ZQUIC server
#[no_mangle]
pub extern "C" fn zquic_server_new(
    bind_addr: *const c_char,
    server_out: *mut *mut CZQuicServer,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_ptr(bind_addr, "bind_addr") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(server_out, "server_out") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let addr_str = match unsafe { from_c_string(bind_addr) } {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid bind address: {}", e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    let addr: SocketAddr = match addr_str.parse() {
        Ok(a) => a,
        Err(e) => {
            error!("Failed to parse bind address {}: {}", addr_str, e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    // Create server with default config
    let config = ZQuicConfig {
        port: addr.port(),
        ..Default::default()
    };

    match ZQuicContext::new(config) {
        Ok(ctx) => {
            let server = ZQuicServer {
                context: Box::into_raw(Box::new(ctx)) as *mut ZQuicContext,
                bind_addr: addr,
                incoming: Arc::new(Mutex::new(None)),
            };

            unsafe {
                *server_out = Box::into_raw(Box::new(server)) as *mut CZQuicServer;
            }
            
            info!("🌐 ZQUIC server created for {}", addr);
            ZQUIC_OK
        }
        Err(e) => {
            error!("Failed to create server: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Start ZQUIC server
#[no_mangle]
pub extern "C" fn zquic_server_start(server: *mut CZQuicServer) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(server, "server") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let server = unsafe { &mut *(server as *mut ZQuicServer) };
    let ctx = unsafe { &mut *server.context };

    let rt = get_runtime();
    
    match rt.block_on(async { ctx.create_endpoint().await }) {
        Ok(()) => {
            info!("✅ ZQUIC server started on {}", server.bind_addr);
            ZQUIC_OK
        }
        Err(e) => {
            error!("Failed to start server: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Accept incoming connection (blocking)
#[no_mangle]
pub extern "C" fn zquic_server_accept_connection(
    server: *mut CZQuicServer,
    conn_out: *mut *mut CZQuicConnection,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(server, "server") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(conn_out, "conn_out") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let server = unsafe { &mut *(server as *mut ZQuicServer) };
    let ctx = unsafe { &mut *server.context };

    if ctx.endpoint.is_none() {
        error!("Server endpoint not created");
        return ZQUIC_ERROR;
    }

    let rt = get_runtime();
    
    match rt.block_on(async {
        let endpoint = ctx.endpoint.as_ref().unwrap();
        match endpoint.accept().await {
            Some(incoming_conn) => {
                match incoming_conn.await {
                    Ok(conn) => {
                        let mut counter = ctx.connection_counter.lock().await;
                        *counter += 1;
                        let conn_id = *counter;
                        
                        let zquic_conn = ZQuicConnection::new(conn_id, conn);
                        let boxed_conn = Box::new(zquic_conn);
                        
                        // Store in context
                        let mut connections = ctx.connections.write().await;
                        connections.insert(conn_id, Arc::clone(&boxed_conn.inner));
                        
                        info!("🔗 Accepted connection #{}", conn_id);
                        Ok(Box::into_raw(boxed_conn))
                    }
                    Err(e) => {
                        error!("Connection failed: {}", e);
                        Err(anyhow!("Connection failed"))
                    }
                }
            }
            None => {
                debug!("No more incoming connections");
                Err(anyhow!("No connections"))
            }
        }
    }) {
        Ok(conn_ptr) => {
            unsafe {
                *conn_out = conn_ptr as *mut CZQuicConnection;
            }
            ZQUIC_OK
        }
        Err(_) => ZQUIC_ERROR,
    }
}

/// Destroy ZQUIC server
#[no_mangle]
pub extern "C" fn zquic_server_destroy(server: *mut CZQuicServer) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(server, "server") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        let server = Box::from_raw(server as *mut ZQuicServer);
        let _ = Box::from_raw(server.context);
    }
    
    info!("🗑️  ZQUIC server destroyed");
    ZQUIC_OK
}

// ============================================================================
// CONNECTION OPERATIONS
// ============================================================================

/// Create client connection to remote peer
#[no_mangle]
pub extern "C" fn zquic_connection_create(
    ctx: *mut CZQuicContext,
    remote_addr: *const c_char,
    conn_out: *mut *mut CZQuicConnection,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(ctx, "ctx") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_ptr(remote_addr, "remote_addr") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(conn_out, "conn_out") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let addr_str = match unsafe { from_c_string(remote_addr) } {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid remote address: {}", e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    let ctx = unsafe { &mut *(ctx as *mut ZQuicContext) };
    let rt = get_runtime();

    match rt.block_on(async {
        // Create client endpoint if needed
        if ctx.endpoint.is_none() {
            let crypto_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SkipVerification))
                .with_no_client_auth();
            
            let client_config = quinn::ClientConfig::new(Arc::new(
                quinn::crypto::rustls::QuicClientConfig::try_from(crypto_config)?
            ));
            
            let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
            endpoint.set_default_client_config(client_config);
            ctx.endpoint = Some(endpoint);
        }

        let endpoint = ctx.endpoint.as_ref().unwrap();
        let conn = endpoint
            .connect(addr_str.parse()?, "localhost")?
            .await?;

        let mut counter = ctx.connection_counter.lock().await;
        *counter += 1;
        let conn_id = *counter;

        let zquic_conn = ZQuicConnection::new(conn_id, conn);
        
        // Store in context
        let mut connections = ctx.connections.write().await;
        connections.insert(conn_id, Arc::clone(&zquic_conn.inner));

        info!("🔗 Connected to {} as connection #{}", addr_str, conn_id);
        Ok::<Box<ZQuicConnection>, anyhow::Error>(Box::new(zquic_conn))
    }) {
        Ok(conn) => {
            unsafe {
                *conn_out = Box::into_raw(conn) as *mut CZQuicConnection;
            }
            ZQUIC_OK
        }
        Err(e) => {
            error!("Connection failed: {}", e);
            ZQUIC_ERROR_CONNECTION_FAILED
        }
    }
}

/// Accept bidirectional stream from connection
#[no_mangle]
pub extern "C" fn zquic_connection_accept_stream(
    conn: *mut CZQuicConnection,
    stream_out: *mut *mut CZQuicStream,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(conn, "conn") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(stream_out, "stream_out") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let conn = unsafe { &mut *(conn as *mut ZQuicConnection) };
    let rt = get_runtime();

    match rt.block_on(async { conn.accept_stream().await }) {
        Ok(Some(stream)) => {
            unsafe {
                *stream_out = Box::into_raw(Box::new(stream)) as *mut CZQuicStream;
            }
            debug!("📡 Stream accepted on connection #{}", conn.id);
            ZQUIC_OK
        }
        Ok(None) => {
            debug!("Connection #{} closed", conn.id);
            ZQUIC_ERROR
        }
        Err(e) => {
            error!("Failed to accept stream: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Close connection
#[no_mangle]
pub extern "C" fn zquic_connection_close(conn: *mut CZQuicConnection) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(conn, "conn") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let conn = unsafe { Box::from_raw(conn as *mut ZQuicConnection) };
    conn.inner.close(0u8.into(), b"Normal close");
    
    info!("🔒 Connection #{} closed", conn.id);
    ZQUIC_OK
}

// ============================================================================
// STREAM OPERATIONS
// ============================================================================

/// Read data from stream
#[no_mangle]
pub extern "C" fn zquic_stream_read(
    stream: *mut CZQuicStream,
    buffer: *mut u8,
    buffer_len: usize,
    bytes_read: *mut usize,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(stream, "stream") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_output_buffer(buffer, buffer_len, "buffer") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_mut_ptr(bytes_read, "bytes_read") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let stream = unsafe { &*(stream as *mut ZQuicStream) };
    let buffer_slice = unsafe { slice::from_raw_parts_mut(buffer, buffer_len) };
    let rt = get_runtime();

    match rt.block_on(async { stream.read(buffer_slice).await }) {
        Ok(n) => {
            unsafe { *bytes_read = n; }
            debug!("📥 Read {} bytes from stream #{}", n, stream.id);
            ZQUIC_OK
        }
        Err(e) => {
            error!("Stream read error: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Write data to stream
#[no_mangle]
pub extern "C" fn zquic_stream_write(
    stream: *mut CZQuicStream,
    data: *const u8,
    data_len: usize,
) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(stream, "stream") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }
    
    if let Err(e) = FfiSafety::validate_buffer(data, data_len, "data") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let stream = unsafe { &*(stream as *mut ZQuicStream) };
    let data_slice = unsafe { slice::from_raw_parts(data, data_len) };
    let rt = get_runtime();

    match rt.block_on(async { stream.write(data_slice).await }) {
        Ok(_) => {
            debug!("📤 Wrote {} bytes to stream #{}", data_len, stream.id);
            ZQUIC_OK
        }
        Err(e) => {
            error!("Stream write error: {}", e);
            ZQUIC_ERROR
        }
    }
}

/// Close stream
#[no_mangle]
pub extern "C" fn zquic_stream_close(stream: *mut CZQuicStream) -> c_int {
    // Validate input parameters
    if let Err(e) = FfiSafety::validate_mut_ptr(stream, "stream") {
        error!("FFI validation failed: {}", e);
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let stream = unsafe { Box::from_raw(stream as *mut ZQuicStream) };
    let rt = get_runtime();

    match rt.block_on(async { stream.close().await }) {
        Ok(_) => {
            debug!("🔒 Stream #{} closed", stream.id);
            ZQUIC_OK
        }
        Err(e) => {
            error!("Stream close error: {}", e);
            ZQUIC_ERROR
        }
    }
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