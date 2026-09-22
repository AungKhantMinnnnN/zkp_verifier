use bytes::{Buf, BufMut, BytesMut};
use serde::{de::DeserializeOwned, Serialize};
use std::marker::PhantomData;
use tokio_util::codec::{Decoder, Encoder};
use crate::zkp_core_engine::ZkpError;

/// Maximum payload size permitted (64 KB) to avoid buffer overflow / DoS attacks
pub const MAX_FRAME_SIZE: usize = 64 * 1024;

/// Length-delimited binary codec for serializing and deserializing typed messages over TCP
/// 
/// Frame Layout:
/// +-----------------------------+------------------------------------+
/// | 4-byte payload length (u32) | Binary payload bytes (bincode)    |
/// +-----------------------------+------------------------------------+
#[derive(Debug, Clone)]
pub struct ZkpMessageCodec<ItemOut, ItemIn> {
    max_frame_size: usize,
    _phantom: PhantomData<(ItemOut, ItemIn)>,
}

impl<ItemOut, ItemIn> Default for ZkpMessageCodec<ItemOut, ItemIn> {
    fn default() -> Self {
        Self::new()
    }
}

impl<ItemOut, ItemIn> ZkpMessageCodec<ItemOut, ItemIn> {
    pub fn new() -> Self {
        Self {
            max_frame_size: MAX_FRAME_SIZE,
            _phantom: PhantomData,
        }
    }

    pub fn with_max_frame_size(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            _phantom: PhantomData,
        }
    }
}

impl<ItemOut: Serialize, ItemIn> Encoder<ItemOut> for ZkpMessageCodec<ItemOut, ItemIn> {
    type Error = ZkpError;

    fn encode(&mut self, item: ItemOut, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let payload = bincode::serialize(&item)
            .map_err(|e| ZkpError::SerializationError(format!("Encoding failed: {e}")))?;

        if payload.len() > self.max_frame_size {
            return Err(ZkpError::SerializationError(format!(
                "Message payload exceeds maximum frame size: {} > {}",
                payload.len(),
                self.max_frame_size
            )));
        }

        // Reserve space for 4-byte header + payload
        dst.reserve(4 + payload.len());
        dst.put_u32(payload.len() as u32);
        dst.put_slice(&payload);
        Ok(())
    }
}

impl<ItemOut, ItemIn: DeserializeOwned> Decoder for ZkpMessageCodec<ItemOut, ItemIn> {
    type Item = ItemIn;
    type Error = ZkpError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if src.len() < 4 {
            // Wait for at least the 4-byte length header
            return Ok(None);
        }

        // Read 4-byte length prefix without advancing read cursor yet
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let frame_len = u32::from_be_bytes(length_bytes) as usize;

        if frame_len > self.max_frame_size {
            return Err(ZkpError::SerializationError(format!(
                "Frame length exceeds allowed limit: {} > {}",
                frame_len, self.max_frame_size
            )));
        }

        if src.len() < 4 + frame_len {
            // Full frame hasn't arrived yet; reserve required space and wait
            src.reserve(4 + frame_len - src.len());
            return Ok(None);
        }

        // Advance past the 4-byte length header
        src.advance(4);

        // Take payload slice
        let payload_bytes = src.split_to(frame_len);

        let item: ItemIn = bincode::deserialize(&payload_bytes)
            .map_err(|e| ZkpError::SerializationError(format!("Decoding failed: {e}")))?;

        Ok(Some(item))
    }
}
