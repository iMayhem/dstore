use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const K: usize = 8;
pub const ALPHA: usize = 3;

pub type NodeId = [u8; 32];

pub const MAX_DATAGRAM_SIZE: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub tcp_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    // Core Kademlia
    Ping { id: NodeId, tcp_port: u16 },
    Pong { id: NodeId, tcp_port: u16 },
    Store { id: NodeId, key: NodeId, value: Vec<u8> },
    StoreOk { id: NodeId, key: NodeId },
    FindNode { id: NodeId, target: NodeId },
    FindNodeOk { id: NodeId, nodes: Vec<NodeInfo> },
    FindValue { id: NodeId, key: NodeId },
    FindValueOk { id: NodeId, value: Option<Vec<u8>>, nodes: Vec<NodeInfo> },

    // NAT traversal — address discovery
    FindAddr { id: NodeId },
    FindAddrOk { id: NodeId, addr: SocketAddr },

    // NAT traversal — hole punching through a relay
    HolePunch { id: NodeId, target_id: NodeId, target_addr: SocketAddr },
    HolePunchNotify { source_id: NodeId, source_addr: SocketAddr },
    HolePunchOk { id: NodeId },
}

pub fn xor_distance(a: &NodeId, b: &NodeId) -> NodeId {
    let mut dist = [0u8; 32];
    for i in 0..32 {
        dist[i] = a[i] ^ b[i];
    }
    dist
}

pub fn leading_zeros(id: &NodeId) -> u32 {
    let mut count = 0;
    for &byte in id {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

pub fn bucket_index(local: &NodeId, other: &NodeId) -> usize {
    let dist = xor_distance(local, other);
    let lz = leading_zeros(&dist);
    if lz >= 255 {
        255
    } else {
        (255 - lz) as usize
    }
}

impl Message {
    pub fn sender_id(&self) -> Option<NodeId> {
        match self {
            Message::Ping { id, .. }
            | Message::Pong { id, .. }
            | Message::Store { id, .. }
            | Message::StoreOk { id, .. }
            | Message::FindNode { id, .. }
            | Message::FindNodeOk { id, .. }
            | Message::FindValue { id, .. }
            | Message::FindValueOk { id, .. }
            | Message::FindAddr { id }
            | Message::FindAddrOk { id, .. }
            | Message::HolePunch { id, .. }
            | Message::HolePunchNotify { source_id: id, .. }
            | Message::HolePunchOk { id } => Some(*id),
        }
    }
}

pub fn generate_node_id() -> NodeId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        .to_le_bytes());
    hasher.update(rand::random::<[u8; 16]>());
    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result);
    id
}
