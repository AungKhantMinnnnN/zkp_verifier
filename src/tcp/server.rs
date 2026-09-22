use std::net::SocketAddr;
use std::sync::Arc;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_util::codec::Framed;

use crate::codec::ZkpMessageCodec;
use crate::protocol::{AuthRequest, AuthResponse};
use crate::replay::ReplayProtector;
use crate::storage::UserRegistry;
use crate::zkp_core_engine::{ZkpEngine, ZkpError};

pub struct BankServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    registry: Arc<UserRegistry>,
    replay_protector: Arc<ReplayProtector>,
}

impl BankServer {
    /// Bind the server to the provided address (e.g. "127.0.0.1:8080" or "127.0.0.1:0")
    pub async fn bind(addr: &str) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        let registry = Arc::new(UserRegistry::in_memory().expect("Failed to init default registry"));
        let replay_protector = Arc::new(ReplayProtector::default());

        Ok(Self {
            listener,
            local_addr,
            registry,
            replay_protector,
        })
    }

    /// Attach a persistent or custom UserRegistry
    pub fn with_registry(mut self, registry: UserRegistry) -> Self {
        self.registry = Arc::new(registry);
        self
    }

    /// Attach a custom ReplayProtector
    pub fn with_replay_protector(mut self, protector: ReplayProtector) -> Self {
        self.replay_protector = Arc::new(protector);
        self
    }

    /// Access the registry
    pub fn registry(&self) -> Arc<UserRegistry> {
        Arc::clone(&self.registry)
    }

    /// Access the replay protector
    pub fn replay_protector(&self) -> Arc<ReplayProtector> {
        Arc::clone(&self.replay_protector)
    }

    /// Returns the bound local socket address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Run the server loop until a shutdown signal is received
    pub async fn run(self, mut shutdown_rx: watch::Receiver<bool>) -> Result<(), std::io::Error> {
        println!("[Bank Verifier] Server listening on {}", self.local_addr);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        println!("[Bank Verifier] Shutdown signal received. Stopping server.");
                        break;
                    }
                }
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok((stream, client_addr)) => {
                            let reg = Arc::clone(&self.registry);
                            let rep = Arc::clone(&self.replay_protector);
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, client_addr, reg, rep).await {
                                    eprintln!("[Bank Verifier] Error handling client {}: {:?}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("[Bank Verifier] Failed to accept connection: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle an individual incoming framed TCP connection
    async fn handle_connection(
        stream: TcpStream,
        client_addr: SocketAddr,
        registry: Arc<UserRegistry>,
        replay_protector: Arc<ReplayProtector>,
    ) -> Result<(), ZkpError> {
        // Framed sink/stream: Encodes AuthResponse, Decodes AuthRequest
        let mut framed = Framed::new(stream, ZkpMessageCodec::<AuthResponse, AuthRequest>::new());

        while let Some(msg_result) = framed.next().await {
            let request = match msg_result {
                Ok(req) => req,
                Err(e) => {
                    eprintln!("[Bank Verifier] Codec decode error from {}: {:?}", client_addr, e);
                    let resp = AuthResponse {
                        user_id: "unknown".into(),
                        success: false,
                        message: format!("Malformed packet: {e}"),
                    };
                    let _ = framed.send(resp).await;
                    return Err(e);
                }
            };

            println!(
                "[Bank Verifier] Received verification request from '{}' ({})",
                request.user_id, client_addr
            );

            // 1. Persistent Storage Check: Lookup registered public key for user
            let registered_pk = match registry.get_public_key(&request.user_id) {
                Ok(Some(pk)) => pk,
                Ok(None) => {
                    let msg = format!("Authentication failed: User '{}' is not registered with bank", request.user_id);
                    println!("[Bank Verifier] Outcome for '{}': success=false, message='{}'", request.user_id, msg);
                    let resp = AuthResponse {
                        user_id: request.user_id,
                        success: false,
                        message: msg,
                    };
                    framed.send(resp).await?;
                    continue;
                }
                Err(e) => {
                    let msg = format!("Storage lookup error: {e}");
                    let resp = AuthResponse {
                        user_id: request.user_id,
                        success: false,
                        message: msg,
                    };
                    framed.send(resp).await?;
                    continue;
                }
            };

            // 2. Mismatched Public Key Check: Request PK must match stored PK
            if request.public_key != registered_pk.to_bytes() {
                let msg = "Authentication failed: Public key does not match bank records".to_string();
                println!("[Bank Verifier] Outcome for '{}': success=false, message='{}'", request.user_id, msg);
                let resp = AuthResponse {
                    user_id: request.user_id,
                    success: false,
                    message: msg,
                };
                framed.send(resp).await?;
                continue;
            }

            // 3. Replay Attack & Freshness Check: Validates timestamp and ensures nonce has not been reused
            if let Err(replay_err) = replay_protector.check_and_record(&request.user_id, &request.proof) {
                let msg = format!("Security rejection: {replay_err}");
                println!("[Bank Verifier] Outcome for '{}': success=false, message='{}'", request.user_id, msg);
                let resp = AuthResponse {
                    user_id: request.user_id,
                    success: false,
                    message: msg,
                };
                framed.send(resp).await?;
                continue;
            }

            // 4. Cryptographic Schnorr ZKP Verification
            let (is_valid, message) = match ZkpEngine::verify(&registered_pk.0, &request.proof) {
                Ok(true) => (
                    true,
                    format!("Identity verified successfully for user '{}'.", request.user_id),
                ),
                Ok(false) => (
                    false,
                    "Verification failed: Mathematical proof check did not match public key.".into(),
                ),
                Err(e) => (false, format!("Cryptographic verification error: {e}")),
            };

            let response = AuthResponse {
                user_id: request.user_id.clone(),
                success: is_valid,
                message: message.clone(),
            };

            println!(
                "[Bank Verifier] Outcome for '{}': success={}, message='{}'",
                request.user_id, is_valid, message
            );

            framed.send(response).await?;
        }

        Ok(())
    }
}
