use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Instant;

use crate::net::protocol::{bucket_index, xor_distance, NodeId, NodeInfo, K};

#[derive(Debug, Clone)]
pub struct Contact {
    pub id: NodeId,
    pub addr: SocketAddr,
    pub tcp_port: u16,
    pub last_seen: Instant,
}

impl Contact {
    pub fn new(id: NodeId, addr: SocketAddr, tcp_port: u16) -> Self {
        Contact {
            id,
            addr,
            tcp_port,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KBucket {
    pub contacts: VecDeque<Contact>,
}

impl Default for KBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl KBucket {
    pub fn new() -> Self {
        KBucket {
            contacts: VecDeque::with_capacity(K),
        }
    }

    pub fn is_full(&self) -> bool {
        self.contacts.len() >= K
    }

    pub fn contains(&self, id: &NodeId) -> bool {
        self.contacts.iter().any(|c| c.id == *id)
    }

    pub fn get(&self, id: &NodeId) -> Option<&Contact> {
        self.contacts.iter().find(|c| c.id == *id)
    }

    pub fn insert(&mut self, id: NodeId, addr: SocketAddr, tcp_port: u16) -> InsertResult {
        if let Some(c) = self.contacts.iter_mut().find(|c| c.id == id) {
            c.last_seen = Instant::now();
            c.tcp_port = tcp_port;
            return InsertResult::Updated;
        }
        if self.contacts.len() < K {
            self.contacts.push_back(Contact::new(id, addr, tcp_port));
            return InsertResult::Added;
        }
        InsertResult::Full
    }

    pub fn remove(&mut self, id: &NodeId) {
        self.contacts.retain(|c| c.id != *id);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Contact> {
        self.contacts.iter()
    }

    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let mut candidates: Vec<(NodeId, NodeInfo)> = self
            .contacts
            .iter()
            .map(|c| {
                let dist = xor_distance(target, &c.id);
                let info = NodeInfo { id: c.id, addr: c.addr, tcp_port: c.tcp_port };
                (dist, info)
            })
            .collect();
        candidates.sort_by_key(|a| a.0);
        candidates.into_iter().take(count).map(|(_, info)| info).collect()
    }
}

#[derive(Debug, PartialEq)]
pub enum InsertResult {
    Added,
    Updated,
    Full,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub local_id: NodeId,
    buckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new(local_id: NodeId) -> Self {
        RoutingTable {
            local_id,
            buckets: vec![KBucket::new(); 256],
        }
    }

    pub fn bucket_index(&self, id: &NodeId) -> usize {
        bucket_index(&self.local_id, id)
    }

    pub fn bucket(&self, id: &NodeId) -> &KBucket {
        let idx = self.bucket_index(id);
        &self.buckets[idx]
    }

    pub fn bucket_mut(&mut self, id: &NodeId) -> &mut KBucket {
        let idx = self.bucket_index(id);
        &mut self.buckets[idx]
    }

    pub fn insert(&mut self, id: NodeId, addr: SocketAddr, tcp_port: u16) -> InsertResult {
        if id == self.local_id {
            return InsertResult::Updated;
        }
        let idx = self.bucket_index(&id);
        self.buckets[idx].insert(id, addr, tcp_port)
    }

    pub fn remove(&mut self, id: &NodeId) {
        if *id == self.local_id {
            return;
        }
        let idx = self.bucket_index(id);
        self.buckets[idx].remove(id);
    }

    pub fn contains(&self, id: &NodeId) -> bool {
        if *id == self.local_id {
            return true;
        }
        let idx = self.bucket_index(id);
        self.buckets[idx].contains(id)
    }

    pub fn closest(&self, target: &NodeId, count: usize) -> Vec<NodeInfo> {
        let idx = self.bucket_index(target);
        let mut candidates = Vec::new();

        // Gather from the target bucket and neighboring buckets
        for offset in 0..256 {
            let low = idx.saturating_sub(offset);
            let high = idx + offset;
            if high < 256 {
                candidates.extend(self.buckets[high].closest(target, count));
            }
            if low != high && low < 256 {
                candidates.extend(self.buckets[low].closest(target, count));
            }
            if candidates.len() >= count * 2 {
                break;
            }
        }

        candidates.sort_by(|a, b| {
            xor_distance(target, &a.id).cmp(&xor_distance(target, &b.id))
        });
        candidates.truncate(count);
        candidates
    }

    pub fn all_nodes(&self) -> Vec<NodeInfo> {
        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for contact in bucket.iter() {
                nodes.push(NodeInfo {
                    id: contact.id,
                    addr: contact.addr,
                    tcp_port: contact.tcp_port,
                });
            }
        }
        nodes
    }
}
