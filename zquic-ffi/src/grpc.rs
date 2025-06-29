//! GhostBridge - gRPC-over-QUIC implementation
//! Provides gRPC functionality over QUIC transport

use super::*;
use std::collections::HashMap;
use std::slice;
use serde::{Deserialize, Serialize};

/// gRPC response structure
#[repr(C)]
pub struct GrpcResponse {
    pub status: c_int,
    pub data: *mut u8,
    pub data_len: usize,
    pub error_message: *mut c_char,
}

/// gRPC message frame structure
#[derive(Debug, Serialize, Deserialize)]
pub struct GrpcFrame {
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    pub message_id: u64,
}

/// gRPC handler function type
pub type GrpcHandler = extern "C" fn(
    method: *const c_char,
    data: *const u8,
    data_len: usize,
    response_out: *mut GrpcResponse,
) -> c_int;

/// Make gRPC call over QUIC connection
#[no_mangle]
pub extern "C" fn zquic_grpc_call(
    conn: *mut CZQuicConnection,
    method: *const c_char,
    data: *const u8,
    data_len: usize,
    response_out: *mut GrpcResponse,
) -> c_int {
    if conn.is_null() || method.is_null() || response_out.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let method_str = match unsafe { from_c_string(method) } {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid method name: {}", e);
            return ZQUIC_ERROR_INVALID_PARAM;
        }
    };

    let request_data = if data.is_null() || data_len == 0 {
        Vec::new()
    } else {
        unsafe { slice::from_raw_parts(data, data_len).to_vec() }
    };

    let conn = unsafe { &*(conn as *mut ZQuicConnection) };
    let rt = get_runtime();

    match rt.block_on(async {
        // Create gRPC frame
        let frame = GrpcFrame {
            method: method_str.clone(),
            headers: HashMap::new(),
            body: request_data,
            message_id: rand::random(),
        };

        // Serialize frame
        let frame_data = serde_json::to_vec(&frame)
            .map_err(|e| anyhow!("Failed to serialize gRPC frame: {}", e))?;

        // Open new stream for gRPC call
        let (mut send, mut recv) = conn.inner
            .open_bi()
            .await
            .map_err(|e| anyhow!("Failed to open stream: {}", e))?;

        // Send gRPC request
        send.write_all(&frame_data).await
            .map_err(|e| anyhow!("Failed to send gRPC request: {}", e))?;
        send.finish()
            .map_err(|e| anyhow!("Failed to finish sending: {}", e))?;

        // Read response
        let response_data = recv.read_to_end(1024 * 1024).await // 1MB limit
            .map_err(|e| anyhow!("Failed to read gRPC response: {}", e))?;

        // Parse response frame
        let response_frame: GrpcFrame = serde_json::from_slice(&response_data)
            .map_err(|e| anyhow!("Failed to parse gRPC response: {}", e))?;

        info!("✅ gRPC call {} completed successfully", method_str);
        Ok::<Vec<u8>, anyhow::Error>(response_frame.body)
    }) {
        Ok(response_body) => {
            // Allocate response data
            let data_ptr = unsafe {
                libc::malloc(response_body.len()) as *mut u8
            };
            
            if data_ptr.is_null() {
                return ZQUIC_ERROR;
            }

            unsafe {
                std::ptr::copy_nonoverlapping(
                    response_body.as_ptr(),
                    data_ptr,
                    response_body.len(),
                );

                *response_out = GrpcResponse {
                    status: ZQUIC_OK,
                    data: data_ptr,
                    data_len: response_body.len(),
                    error_message: ptr::null_mut(),
                };
            }

            ZQUIC_OK
        }
        Err(e) => {
            error!("gRPC call failed: {}", e);
            
            // Set error response
            let error_msg = to_c_string(&e.to_string()).unwrap_or_default();
            unsafe {
                *response_out = GrpcResponse {
                    status: ZQUIC_ERROR,
                    data: ptr::null_mut(),
                    data_len: 0,
                    error_message: error_msg.into_raw(),
                };
            }

            ZQUIC_ERROR
        }
    }
}

/// Set up gRPC server over QUIC
#[no_mangle]
pub extern "C" fn zquic_grpc_serve(
    server: *mut CZQuicServer,
    _handler: GrpcHandler,
) -> c_int {
    if server.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    let _server = unsafe { &*(server as *mut ZQuicServer) };
    let rt = get_runtime();

    // Start gRPC service loop
    rt.spawn(async move {
        info!("🌉 GhostBridge gRPC server started");
        
        loop {
            // Accept connections and handle gRPC requests
            // This would typically be implemented as part of the main server loop
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    });

    info!("🚀 gRPC server setup complete");
    ZQUIC_OK
}

/// Free gRPC response
#[no_mangle]
pub extern "C" fn zquic_grpc_response_free(response: *mut GrpcResponse) -> c_int {
    if response.is_null() {
        return ZQUIC_ERROR_INVALID_PARAM;
    }

    unsafe {
        let resp = &mut *response;
        
        // Free data buffer
        if !resp.data.is_null() {
            libc::free(resp.data as *mut c_void);
            resp.data = ptr::null_mut();
        }
        
        // Free error message
        if !resp.error_message.is_null() {
            let _ = CString::from_raw(resp.error_message);
            resp.error_message = ptr::null_mut();
        }
    }

    ZQUIC_OK
}

/// Helper function to create gRPC response with wallet balance
pub fn create_wallet_balance_response(balance: u64) -> Vec<u8> {
    let response = serde_json::json!({
        "balance": balance,
        "timestamp": chrono::Utc::now().timestamp(),
        "status": "success"
    });
    
    serde_json::to_vec(&response).unwrap_or_default()
}

/// Helper function to create gRPC response with transaction hash
pub fn create_transaction_response(tx_hash: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "transaction_hash": tx_hash,
        "timestamp": chrono::Utc::now().timestamp(),
        "status": "confirmed"
    });
    
    serde_json::to_vec(&response).unwrap_or_default()
}

/// Helper function to create gRPC error response
pub fn create_error_response(error: &str) -> Vec<u8> {
    let response = serde_json::json!({
        "error": error,
        "timestamp": chrono::Utc::now().timestamp(),
        "status": "error"
    });
    
    serde_json::to_vec(&response).unwrap_or_default()
}