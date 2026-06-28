use crate::net::protocol::NodeId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TcpMessage {
    PutChunk { key: NodeId, data: Vec<u8> },
    PutChunkOk { key: NodeId },
    GetChunk { key: NodeId },
    GetChunkOk { key: NodeId, data: Vec<u8> },
    GetChunkNotFound { key: NodeId },
}
