use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

pub const K: usize = 8;
pub const ALPHA: usize = 3;

pub type NodeId = [u8; 32];

pub const MAX_DATAGRAM_SIZE: usize = 4096;
pub const POW_DIFFICULTY: u32 = 16; // leading zero bits required for PoW node ID

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

/// Signed wrapper around every DHT message.
/// `sender_pubkey` is the Ed25519 public key of the sender.
/// `signature` covers the serialized `inner` message.
/// `pow_nonce` is the proof-of-work nonce used to generate the sender's node ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedMessage {
    pub sender_pubkey: [u8; 32],
    pub pow_nonce: u64,
    pub signature: Vec<u8>,
    pub inner: Message,
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

/// Generate a proof-of-work node ID from an Ed25519 public key.
/// The ID is SHA-256(pubkey || nonce) with POW_DIFFICULTY leading zero bits.
/// Returns (id, nonce).
pub fn generate_pow_node_id(pubkey: &[u8; 32]) -> (NodeId, u64) {
    use sha2::{Digest, Sha256};
    loop {
        let nonce: u64 = rand::random();
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.update(nonce.to_le_bytes());
        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result);
        if leading_zeros(&id) >= POW_DIFFICULTY {
            return (id, nonce);
        }
    }
}

/// Check that a PoW node ID is valid for the given pubkey and nonce.
pub fn verify_pow_node_id(id: &NodeId, pubkey: &[u8; 32], nonce: u64) -> bool {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(nonce.to_le_bytes());
    let result = hasher.finalize();
    let computed = &result[..];
    computed == id
}

impl SignedMessage {
    pub fn sign(signing_key: &ed25519_dalek::SigningKey, msg: Message, pow_nonce: u64) -> Result<Self, anyhow::Error> {
        let inner_bytes = bincode::serialize(&msg)?;
        let signature = signing_key.sign(&inner_bytes);
        Ok(SignedMessage {
            sender_pubkey: signing_key.verifying_key().to_bytes(),
            pow_nonce,
            signature: signature.to_bytes().to_vec(),
            inner: msg,
        })
    }

    pub fn verify(&self) -> Result<Message, anyhow::Error> {
        let inner_bytes = bincode::serialize(&self.inner)?;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(&self.sender_pubkey)?;
        let sig = ed25519_dalek::Signature::from_slice(&self.signature)?;
        pk.verify(&inner_bytes, &sig)?;
        // Verify PoW node ID: SHA-256(pubkey || nonce) == sender_id with leading zeros
        if let Some(sender_id) = self.inner.sender_id() {
            if !verify_pow_node_id(&sender_id, &self.sender_pubkey, self.pow_nonce) {
                anyhow::bail!("PoW node ID verification failed");
            }
        }
        Ok(self.inner.clone())
    }
}
