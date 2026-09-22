use futures::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

use crate::codec::ZkpMessageCodec;
use crate::protocol::{AuthRequest, AuthResponse};
use crate::zkp_core_engine::{UserSecretKey, ZkpEngine, ZkpError};

pub struct UserProverClient {
    framed: Framed<TcpStream, ZkpMessageCodec<AuthRequest, AuthResponse>>,
}

impl UserProverClient {
    /// Connect to the Bank Verifier at the specified address (e.g. "127.0.0.1:8080")
    pub async fn connect(addr: &str) -> Result<Self, std::io::Error> {
        let stream = TcpStream::connect(addr).await?;
        let framed = Framed::new(stream, ZkpMessageCodec::<AuthRequest, AuthResponse>::new());
        Ok(Self { framed })
    }

    /// Authenticate to the bank verifier with zero knowledge
    ///
    /// If `tamper` is true, the proof's scalar is maliciously corrupted
    /// to simulate a fraudulent proof and test the verifier's tamper detection.
    pub async fn authenticate(
        &mut self,
        user_id: &str,
        secret_key: &UserSecretKey,
        tamper: bool,
    ) -> Result<AuthResponse, ZkpError> {
        let public_key = secret_key.public_key();
        let mut proof = ZkpEngine::generate_proof(secret_key, &public_key);

        if tamper {
            if let Some(last_byte) = proof.s_scalar.last_mut() {
                *last_byte = last_byte.wrapping_add(1);
            }
        }

        let request = AuthRequest {
            user_id: user_id.to_string(),
            public_key: public_key.to_bytes(),
            proof,
        };

        self.send_raw_request(request).await
    }

    /// Transmit a raw framed request (useful for testing replay attacks and edge cases)
    pub async fn send_raw_request(&mut self, request: AuthRequest) -> Result<AuthResponse, ZkpError> {
        // Send framed request
        self.framed.send(request).await?;

        // Read framed response
        match self.framed.next().await {
            Some(Ok(response)) => Ok(response),
            Some(Err(e)) => Err(e),
            None => Err(ZkpError::SerializationError(
                "Connection closed by server before response was received".into(),
            )),
        }
    }
}
