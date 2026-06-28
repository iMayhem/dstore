use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Mutex;

use crate::net::protocol::{
    generate_node_id, xor_distance, Message, NodeId, NodeInfo, ALPHA, K, MAX_DATAGRAM_SIZE,
};
use crate::net::routing::{InsertResult, RoutingTable};
use crate::net::tcp::TcpMessage;

fn msg_tcp_port(msg: &Message) -> u16 {
    match msg {
        Message::Ping { tcp_port, .. } | Message::Pong { tcp_port, .. } => *tcp_port,
        _ => 0,
    }
}

pub struct DhtNode {
    pub id: NodeId,
    pub routing: Arc<Mutex<RoutingTable>>,
    socket: Arc<UdpSocket>,
    store: Arc<Mutex<HashMap<NodeId, Vec<u8>>>>,
    pending_pings: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
    external_addr: Arc<Mutex<Option<SocketAddr>>>,
    punch_callbacks: Arc<Mutex<HashMap<SocketAddr, tokio::sync::oneshot::Sender<SocketAddr>>>>,
    pub tcp_port: u16,
}

impl DhtNode {
    pub async fn new(addr: SocketAddr) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        let local_addr = socket.local_addr()?;
        let id = generate_node_id();
        tracing::info!("DHT Node ID: {}", hex::encode(id));
        tracing::info!("UDP listening on: {}", local_addr);

        // Bind TCP on port+1, try up to 100 ports in case of conflict
        let mut tcp_port = local_addr.port();
        let tcp_listener = loop {
            tcp_port += 1;
            let tcp_addr = SocketAddr::new(local_addr.ip(), tcp_port);
            match TcpListener::bind(tcp_addr).await {
                Ok(listener) => {
                    tracing::info!("TCP listening on: {}", tcp_addr);
                    break listener;
                }
                Err(_) if tcp_port < local_addr.port() + 100 => continue,
                Err(e) => return Err(e),
            }
        };

        let mut routing = RoutingTable::new(id);
        routing.insert(id, local_addr, tcp_port);
        let store: Arc<Mutex<HashMap<NodeId, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn TCP acceptor
        let tcp_store = store.clone();
        tokio::spawn(async move {
            Self::run_tcp_acceptor(tcp_listener, tcp_store).await;
        });

        Ok(DhtNode {
            id,
            routing: Arc::new(Mutex::new(routing)),
            socket: Arc::new(socket),
            store,
            pending_pings: Arc::new(Mutex::new(HashMap::new())),
            external_addr: Arc::new(Mutex::new(None)),
            punch_callbacks: Arc::new(Mutex::new(HashMap::new())),
            tcp_port,
        })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn external_addr(&self) -> Option<SocketAddr> {
        *self.external_addr.lock().await
    }

    pub async fn discover_addr(&self, relay: SocketAddr) -> anyhow::Result<SocketAddr> {
        let msg = Message::FindAddr { id: self.id };
        let resp = self.send_rpc_expect(&msg, relay).await?;
        match resp {
            Message::FindAddrOk { addr, .. } => {
                let mut ea = self.external_addr.lock().await;
                *ea = Some(addr);
                tracing::info!("Discovered external address: {}", addr);
                Ok(addr)
            }
            _ => anyhow::bail!("Unexpected response to FindAddr"),
        }
    }

    pub async fn hole_punch(
        &self,
        relay: SocketAddr,
        target_id: NodeId,
        target_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        tracing::info!("Hole punching to {} ({})", hex::encode(target_id), target_addr);

        let msg = Message::HolePunch {
            id: self.id,
            target_id,
            target_addr,
        };
        let data = bincode::serialize(&msg)?;
        self.socket.send_to(&data, relay).await?;

        // Send a blind packet to start opening our NAT to the target
        let blind = Message::Ping { id: self.id, tcp_port: self.tcp_port };
        if let Ok(data) = bincode::serialize(&blind) {
            self.socket.send_to(&data, target_addr).await.ok();
        }

        // Read until we get a message from the target (proving the pinhole is open)
        let mut buf = vec![0u8; 65535];
        let punch_result = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (len, from) = self.socket.recv_from(&mut buf).await?;
                if from == target_addr {
                    return Ok::<_, anyhow::Error>(from);
                }
                // Still process other messages for routing
                if let Ok(msg) = bincode::deserialize::<Message>(&buf[..len]) {
                    if let Some(id) = msg.sender_id() {
                        self.routing.lock().await.insert(id, from, msg_tcp_port(&msg));
                    }
                }
            }
        })
        .await;

        match punch_result {
            Ok(Ok(addr)) => {
                tracing::info!("Hole punch succeeded, peer at {}", addr);
                Ok(())
            }
            _ => anyhow::bail!("Hole punch timeout to {}", target_addr),
        }
    }

    pub async fn bootstrap(&self, bootstrap_addr: SocketAddr) -> anyhow::Result<()> {
        tracing::info!("Bootstrapping with {}", bootstrap_addr);
        let mut buf = vec![0u8; 65535];
        let msg = Message::Ping { id: self.id, tcp_port: self.tcp_port };
        let data = bincode::serialize(&msg)?;
        self.socket.send_to(&data, bootstrap_addr).await?;

        match tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let (len, from) = self.socket.recv_from(&mut buf).await?;
                if from == bootstrap_addr {
                    if let Ok(msg) = bincode::deserialize::<Message>(&buf[..len]) {
                        return Ok::<_, anyhow::Error>(msg);
                    }
                }
            }
        })
        .await
        {
            Ok(Ok(Message::Pong { id, tcp_port })) => {
                tracing::info!("Bootstrap node responded: {} tcp:{}",
                    hex::encode(id), tcp_port);
                let mut rt = self.routing.lock().await;
                rt.insert(id, bootstrap_addr, tcp_port);
                drop(rt);

                if let Ok(addr) = self.discover_addr(bootstrap_addr).await {
                    tracing::info!("External address: {}", addr);
                }

                self.node_lookup(self.id).await?;
                Ok(())
            }
            Ok(Ok(_)) => anyhow::bail!("Unexpected response from bootstrap"),
            Ok(Err(e)) => Err(e),
            Err(_) => anyhow::bail!("Bootstrap timeout"),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let local_tcp_port = self.tcp_port;
        let local_addr = self.socket.local_addr()?;
        let mut buf = vec![0u8; 65535];
        loop {
            let (len, from) = self.socket.recv_from(&mut buf).await?;
            let data = buf[..len].to_vec();
            let socket = self.socket.clone();
            let routing = self.routing.clone();
            let store = self.store.clone();
            let local_id = self.id;
            let pending_pings = self.pending_pings.clone();
            let external_addr = self.external_addr.clone();
            let punch_callbacks = self.punch_callbacks.clone();

            tokio::spawn(async move {
                if let Ok(msg) = bincode::deserialize::<Message>(&data) {
                    tracing::debug!("Received message from {}: {:?}", from, msg);
                    if let Err(e) = Self::handle_message(
                        socket, routing, store, local_id, local_addr, local_tcp_port,
                        pending_pings, external_addr, punch_callbacks, msg, from,
                    )
                    .await
                    {
                        tracing::warn!("Error handling message from {}: {}", from, e);
                    }
                }
            });
        }
    }

    async fn run_tcp_acceptor(listener: TcpListener, store: Arc<Mutex<HashMap<NodeId, Vec<u8>>>>) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let s = store.clone();
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_tcp_connection(stream, s).await {
                            tracing::warn!("TCP error from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("TCP accept error: {}", e);
                }
            }
        }
    }

    async fn handle_tcp_connection(
        mut stream: TcpStream,
        store: Arc<Mutex<HashMap<NodeId, Vec<u8>>>>,
    ) -> anyhow::Result<()> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            anyhow::bail!("TCP message too large: {} bytes", len);
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let msg: TcpMessage = bincode::deserialize(&buf)?;

        match msg {
            TcpMessage::PutChunk { key, data } => {
                store.lock().await.insert(key, data);
                let resp = TcpMessage::PutChunkOk { key };
                Self::send_tcp_message(&mut stream, &resp).await?;
            }
            TcpMessage::GetChunk { key } => {
                let data = store.lock().await.get(&key).cloned();
                match data {
                    Some(data) => {
                        let resp = TcpMessage::GetChunkOk { key, data };
                        Self::send_tcp_message(&mut stream, &resp).await?;
                    }
                    None => {
                        let resp = TcpMessage::GetChunkNotFound { key };
                        Self::send_tcp_message(&mut stream, &resp).await?;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn send_tcp_message(
        stream: &mut TcpStream,
        msg: &TcpMessage,
    ) -> anyhow::Result<()> {
        let data = bincode::serialize(msg)?;
        let len = (data.len() as u32).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(&data).await?;
        Ok(())
    }

    async fn recv_tcp_message(
        stream: &mut TcpStream,
    ) -> anyhow::Result<TcpMessage> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 1024 * 1024 {
            anyhow::bail!("TCP response too large: {} bytes", len);
        }
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(bincode::deserialize(&buf)?)
    }

    /// Send a chunk to a remote node's TCP port. Used internally by store_value.
    async fn put_chunk_tcp(
        &self,
        addr: SocketAddr,
        tcp_port: u16,
        key: NodeId,
        data: &[u8],
    ) -> anyhow::Result<()> {
        if tcp_port == 0 {
            anyhow::bail!("TCP port unknown for {}", addr);
        }
        let tcp_addr = SocketAddr::new(addr.ip(), tcp_port);
        let mut stream = tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(tcp_addr),
        )
        .await??;

        let msg = TcpMessage::PutChunk {
            key,
            data: data.to_vec(),
        };
        Self::send_tcp_message(&mut stream, &msg).await?;
        let resp = Self::recv_tcp_message(&mut stream).await?;
        match resp {
            TcpMessage::PutChunkOk { .. } => Ok(()),
            _ => anyhow::bail!("unexpected TCP response to PutChunk"),
        }
    }

    /// Fetch a chunk from a remote node's TCP port. Used internally by find_value.
    async fn get_chunk_tcp(
        &self,
        addr: SocketAddr,
        tcp_port: u16,
        key: &NodeId,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        if tcp_port == 0 {
            return Ok(None);
        }
        let tcp_addr = SocketAddr::new(addr.ip(), tcp_port);
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(10),
            TcpStream::connect(tcp_addr),
        )
        .await
        {
            Ok(Ok(s)) => s,
            _ => return Ok(None),
        };

        let msg = TcpMessage::GetChunk { key: *key };
        if Self::send_tcp_message(&mut stream, &msg).await.is_err() {
            return Ok(None);
        }
        match Self::recv_tcp_message(&mut stream).await {
            Ok(TcpMessage::GetChunkOk { data, .. }) => Ok(Some(data)),
            Ok(TcpMessage::GetChunkNotFound { .. }) => Ok(None),
            _ => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_message(
        socket: Arc<UdpSocket>,
        routing: Arc<Mutex<RoutingTable>>,
        store: Arc<Mutex<HashMap<NodeId, Vec<u8>>>>,
        local_id: NodeId,
        local_addr: SocketAddr,
        local_tcp_port: u16,
        pending_pings: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
        external_addr: Arc<Mutex<Option<SocketAddr>>>,
        punch_callbacks: Arc<Mutex<HashMap<SocketAddr, tokio::sync::oneshot::Sender<SocketAddr>>>>,
        msg: Message,
        from: SocketAddr,
    ) -> anyhow::Result<()> {
        // Determine TCP port to use for this peer based on the message type
        let peer_tcp_port = msg_tcp_port(&msg);

        // Update routing table for any message from a known node
        match &msg {
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
            | Message::HolePunchOk { id } => {
                let mut rt = routing.lock().await;
                if rt.insert(*id, from, peer_tcp_port) == InsertResult::Full {
                    let oldest = rt.bucket(id).contacts.front().cloned();
                    drop(rt);
                    if let Some(oldest) = oldest {
                        let ping_msg = Message::Ping { id: local_id, tcp_port: local_tcp_port };
                        if let Ok(data) = bincode::serialize(&ping_msg) {
                            socket.send_to(&data, oldest.addr).await.ok();
                            let mut pp = pending_pings.lock().await;
                            pp.insert(oldest.addr, Instant::now());
                        }
                    }
                }
            }
        }

        // Check if this message completes a pending hole punch
        {
            let mut cbs = punch_callbacks.lock().await;
            if let Some(tx) = cbs.remove(&from) {
                tx.send(from).ok();
            }
        }

        match msg {
            Message::Ping { id: _, tcp_port: _ } => {
                let pong = Message::Pong { id: local_id, tcp_port: local_tcp_port };
                let data = bincode::serialize(&pong)?;
                socket.send_to(&data, from).await?;
            }
            Message::Pong { id: _, tcp_port: _ } => {
                let mut pp = pending_pings.lock().await;
                pp.remove(&from);
            }
            Message::Store { id: _, key, value } => {
                let mut s = store.lock().await;
                s.insert(key, value);
                let ok = Message::StoreOk { id: local_id, key };
                let data = bincode::serialize(&ok)?;
                socket.send_to(&data, from).await?;
            }
            Message::StoreOk { .. } => {}
            Message::FindNode { id: _, target } => {
                let rt = routing.lock().await;
                let mut nodes = rt.closest(&target, K);
                // Include self so requester learns our TCP port
                nodes.push(NodeInfo {
                    id: local_id,
                    addr: local_addr,
                    tcp_port: local_tcp_port,
                });
                drop(rt);
                let resp = Message::FindNodeOk {
                    id: local_id,
                    nodes,
                };
                let data = bincode::serialize(&resp)?;
                socket.send_to(&data, from).await?;
            }
            Message::FindNodeOk { .. } => {}
            Message::FindValue { id: _, key } => {
                let s = store.lock().await;
                // Don't return values over UDP that exceed MAX_DATAGRAM_SIZE.
                // The requester falls back to TCP GetChunk for large values.
                let value = s.get(&key).and_then(|v| {
                    if v.len() <= MAX_DATAGRAM_SIZE {
                        Some(v.clone())
                    } else {
                        None
                    }
                });
                drop(s);
                let rt = routing.lock().await;
                let nodes = rt.closest(&key, K);
                drop(rt);
                let resp = Message::FindValueOk {
                    id: local_id,
                    value,
                    nodes,
                };
                let data = bincode::serialize(&resp)?;
                socket.send_to(&data, from).await?;
            }
            Message::FindValueOk { .. } => {}
            // NAT traversal — address discovery
            Message::FindAddr { id: _ } => {
                let resp = Message::FindAddrOk { id: local_id, addr: from };
                let data = bincode::serialize(&resp)?;
                socket.send_to(&data, from).await?;
            }
            Message::FindAddrOk { addr, .. } => {
                let mut ea = external_addr.lock().await;
                *ea = Some(addr);
                tracing::debug!("Discovered external address: {}", addr);
            }
            // NAT traversal — hole punching
            Message::HolePunch { target_id: _, target_addr, .. } => {
                // We are the relay. Notify the target that someone wants to connect.
                let notify = Message::HolePunchNotify {
                    source_id: local_id,
                    source_addr: from,
                };
                if let Ok(data) = bincode::serialize(&notify) {
                    socket.send_to(&data, target_addr).await.ok();
                }
                let ok = Message::HolePunchOk { id: local_id };
                let data = bincode::serialize(&ok)?;
                socket.send_to(&data, from).await?;
            }
            Message::HolePunchNotify { source_addr, .. } => {
                // Someone wants us to hole-punch. Send a packet to open our NAT.
                let blind = Message::Ping { id: local_id, tcp_port: local_tcp_port };
                if let Ok(data) = bincode::serialize(&blind) {
                    socket.send_to(&data, source_addr).await.ok();
                }
            }
            Message::HolePunchOk { .. } => {}
        }

        Ok(())
    }

    async fn send_rpc(&self, msg: &Message, target: SocketAddr) -> anyhow::Result<Vec<u8>> {
        let data = bincode::serialize(msg)?;
        let mut buf = vec![0u8; 65535];
        self.socket.send_to(&data, target).await?;
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), self.socket.recv_from(&mut buf)).await??;
        if from != target {
            anyhow::bail!("Response from unexpected address: {}", from);
        }
        Ok(buf[..len].to_vec())
    }

    async fn send_rpc_expect(&self, msg: &Message, target: SocketAddr) -> anyhow::Result<Message> {
        let raw = self.send_rpc(msg, target).await?;
        Ok(bincode::deserialize(&raw)?)
    }

    pub async fn node_lookup(&self, target: NodeId) -> anyhow::Result<Vec<NodeInfo>> {
        let initial = {
            let rt = self.routing.lock().await;
            rt.closest(&target, K)
        };

        let mut shortlist: Vec<(NodeId, NodeInfo)> = initial
            .into_iter()
            .map(|n| (xor_distance(&target, &n.id), n))
            .collect();
        shortlist.sort_by_key(|a| a.0);

        let mut queried = std::collections::HashSet::new();
        let mut closest_dist = shortlist.first().map(|(d, _)| *d);

        loop {
            let to_query: Vec<NodeInfo> = shortlist
                .iter()
                .filter(|(_, n)| !queried.contains(&n.addr))
                .take(ALPHA)
                .map(|(_, n)| n.clone())
                .collect();

            if to_query.is_empty() {
                break;
            }

            for node in &to_query {
                queried.insert(node.addr);
                let msg = Message::FindNode {
                    id: self.id,
                    target,
                };
                if let Ok(Message::FindNodeOk { nodes, .. }) = self.send_rpc_expect(&msg, node.addr).await {
                    for n in nodes {
                        {
                            let mut rt = self.routing.lock().await;
                            rt.insert(n.id, n.addr, n.tcp_port);
                        }
                        if !shortlist.iter().any(|(_, existing)| existing.id == n.id)
                            && !queried.contains(&n.addr)
                        {
                            let dist = xor_distance(&target, &n.id);
                            shortlist.push((dist, n));
                        }
                    }
                }
            }

            shortlist.sort_by_key(|a| a.0);
            shortlist.truncate(K * 2);

            let new_closest = shortlist.first().map(|(d, _)| *d);
            if let (Some(new_d), Some(old_d)) = (new_closest, closest_dist) {
                if new_d >= old_d {
                    break;
                }
            }
            closest_dist = new_closest;
        }

        Ok(shortlist.into_iter().take(K).map(|(_, n)| n).collect())
    }

    pub async fn store_value(&self, key: NodeId, value: Vec<u8>) -> anyhow::Result<()> {
        {
            let mut s = self.store.lock().await;
            s.insert(key, value.clone());
        }

        let nodes = self.node_lookup(key).await?;
        let use_tcp = value.len() > MAX_DATAGRAM_SIZE;
        let mut stored_count = 0usize;

        for node in &nodes {
            if use_tcp {
                if let Err(e) = self.put_chunk_tcp(node.addr, node.tcp_port, key, &value).await {
                    tracing::warn!("TCP store to {} failed: {}", node.addr, e);
                } else {
                    stored_count += 1;
                }
            } else {
                let msg = Message::Store {
                    id: self.id,
                    key,
                    value: value.clone(),
                };
                if let Ok(resp) = self.send_rpc_expect(&msg, node.addr).await {
                    if matches!(resp, Message::StoreOk { .. }) {
                        stored_count += 1;
                    }
                }
            }
        }

        tracing::info!("Stored value on {}/{} remote nodes", stored_count, nodes.len());
        Ok(())
    }

    /// Check how many of the K closest peers actually have a copy of the value.
    /// Returns the list of peers that confirmed they have it.
    pub async fn check_replicas(&self, key: &NodeId) -> Vec<NodeInfo> {
        let nodes = {
            let rt = self.routing.lock().await;
            rt.closest(key, K)
        };

        let mut replicas = Vec::new();
        for node in &nodes {
            if node.id == self.id {
                replicas.push(node.clone());
                continue;
            }
            // Try UDP FindValue first (works for small values)
            let msg = Message::FindValue { id: self.id, key: *key };
            if let Ok(Message::FindValueOk { value: Some(_), .. }) =
                self.send_rpc_expect(&msg, node.addr).await
            {
                replicas.push(node.clone());
                continue;
            }
            // Fall back to TCP GetChunk for large values
            if node.tcp_port != 0 {
                if let Ok(Some(_)) = self.get_chunk_tcp(node.addr, node.tcp_port, key).await {
                    replicas.push(node.clone());
                }
            }
        }
        replicas
    }

    /// Ensure a value has at least `target_count` replicas among the network.
    /// Checks peers for existing copies, then distributes to peers that don't have it.
    /// Returns the total number of confirmed replicas (including self).
    pub async fn replicate_value(
        &self,
        key: NodeId,
        value: Vec<u8>,
        target_count: usize,
    ) -> usize {
        {
            let mut s = self.store.lock().await;
            s.insert(key, value.clone());
        }

        let nodes = {
            let rt = self.routing.lock().await;
            rt.closest(&key, K)
        };

        let use_tcp = value.len() > MAX_DATAGRAM_SIZE;
        let mut stored = 1usize; // we have it locally

        for node in &nodes {
            if stored >= target_count {
                break;
            }
            if node.id == self.id {
                continue;
            }

            // Check if peer already has it
            let has_it = if use_tcp {
                if node.tcp_port == 0 {
                    false
                } else {
                    matches!(
                        self.get_chunk_tcp(node.addr, node.tcp_port, &key).await,
                        Ok(Some(_))
                    )
                }
            } else {
                let msg = Message::FindValue { id: self.id, key };
                matches!(
                    self.send_rpc_expect(&msg, node.addr).await,
                    Ok(Message::FindValueOk { value: Some(_), .. })
                )
            };

            if has_it {
                stored += 1;
                continue;
            }

            // Peer doesn't have it — send the value
            let ok = if use_tcp {
                self.put_chunk_tcp(node.addr, node.tcp_port, key, &value)
                    .await
                    .is_ok()
            } else {
                let msg = Message::Store {
                    id: self.id,
                    key,
                    value: value.clone(),
                };
                matches!(
                    self.send_rpc_expect(&msg, node.addr).await,
                    Ok(Message::StoreOk { .. })
                )
            };

            if ok {
                stored += 1;
            }
        }

        tracing::debug!(
            "Replicated value {}: {}/{} replicas (target {})",
            hex::encode(key),
            stored,
            nodes.len() + 1,
            target_count,
        );
        stored
    }

    /// Spawn a background task that periodically refreshes buckets and re-publishes values.
    /// Call this once after bootstrapping if the node will run for a while.
    pub fn start_repair_task(&self) {
        let routing = self.routing.clone();
        let store = self.store.clone();
        let socket = self.socket.clone();
        let local_id = self.id;

        tokio::spawn(async move {
            let mut bucket_idx = 0usize;
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;

                // 1. Refresh a bucket by doing a random lookup in its range
                let target = {
                    let mut id = local_id;
                    // Flip a random bit in the bucket's range
                    let bit_index = 255 - bucket_idx;
                    if bit_index < 256 {
                        let byte_idx = bit_index / 8;
                        let bit_offset = bit_index % 8;
                        id[byte_idx] ^= 1 << bit_offset;
                    }
                    id
                };

                tracing::debug!("Refreshing bucket {} via lookup", bucket_idx);

                // We can't call self.node_lookup here because we're in a spawned task
                // Instead, send a FindNode manually to a known node
                let target_closest = {
                    let rt = routing.lock().await;
                    rt.closest(&target, K).first().cloned()
                };

                if let Some(closest) = target_closest {
                    let msg = Message::FindNode {
                        id: local_id,
                        target,
                    };
                    if let Ok(data) = bincode::serialize(&msg) {
                        let mut buf = vec![0u8; 65535];
                        if socket.send_to(&data, closest.addr).await.is_ok() {
                            if let Ok(Ok((len, _))) = tokio::time::timeout(
                                Duration::from_secs(3),
                                socket.recv_from(&mut buf),
                            )
                            .await
                            {
                                if let Ok(Message::FindNodeOk { nodes, .. }) = bincode::deserialize::<Message>(&buf[..len]) {
                                    let mut rt = routing.lock().await;
                                    for n in nodes {
                                        rt.insert(n.id, n.addr, n.tcp_port);
                                    }
                                }
                            }
                        }
                    }
                }

                bucket_idx = (bucket_idx + 1) % 256;

                // 2. Every 5th tick (roughly every 150s), verify + replenish replicas
                if bucket_idx.is_multiple_of(5) {
                    let snapshot = {
                        let s = store.lock().await;
                        s.iter().map(|(k, v)| (*k, v.clone())).collect::<Vec<_>>()
                    };
                    if !snapshot.is_empty() {
                        let target = (K / 2).max(2);
                        tracing::debug!(
                            "Anti-entropy: checking {} values (target {} replicas)",
                            snapshot.len(),
                            target
                        );
                        for (key, value) in &snapshot {
                            let nodes = {
                                let rt = routing.lock().await;
                                rt.closest(key, K)
                            };

                            // First check which nodes already have it, count replicas
                            let mut have_count = 1usize; // self
                            let mut missing: Vec<&NodeInfo> = Vec::new();

                            for node in &nodes {
                                if node.id == local_id {
                                    continue;
                                }
                                let use_tcp = value.len() > MAX_DATAGRAM_SIZE;
                                let has_it = if use_tcp {
                                    if node.tcp_port == 0 {
                                        false
                                    } else {
                                        let tcp_addr = SocketAddr::new(
                                            node.addr.ip(),
                                            node.tcp_port,
                                        );
                                        let mut stream = match tokio::time::timeout(
                                            Duration::from_secs(5),
                                            TcpStream::connect(tcp_addr),
                                        )
                                        .await
                                        {
                                            Ok(Ok(s)) => s,
                                            _ => {
                                                have_count += 0;
                                                continue;
                                            }
                                        };
                                        let query_msg = TcpMessage::GetChunk { key: *key };
                                        Self::send_tcp_message(&mut stream, &query_msg)
                                            .await
                                            .is_ok()
                                            && Self::recv_tcp_message(&mut stream)
                                                .await
                                                .is_ok_and(|r| {
                                                    matches!(r, TcpMessage::GetChunkOk { .. })
                                                })
                                    }
                                } else {
                                    let msg = Message::FindValue {
                                        id: local_id,
                                        key: *key,
                                    };
                                    matches!(
                                        Self::send_rpc_raw(&msg, node.addr, &socket).await,
                                        Ok(Message::FindValueOk {
                                            value: Some(_), ..
                                        })
                                    )
                                };

                                if has_it {
                                    have_count += 1;
                                } else {
                                    missing.push(node);
                                }
                            }

                            // Replicate to peers that don't have it, up to target
                            if have_count < target {
                                let use_tcp = value.len() > MAX_DATAGRAM_SIZE;
                                for node in &missing {
                                    if have_count >= target {
                                        break;
                                    }
                                    let ok = if use_tcp {
                                        if node.tcp_port == 0 {
                                            continue;
                                        }
                                        let tcp_addr = SocketAddr::new(
                                            node.addr.ip(),
                                            node.tcp_port,
                                        );
                                        let mut stream = match tokio::time::timeout(
                                            Duration::from_secs(5),
                                            TcpStream::connect(tcp_addr),
                                        )
                                        .await
                                        {
                                            Ok(Ok(s)) => s,
                                            _ => continue,
                                        };
                                        let put_msg = TcpMessage::PutChunk {
                                            key: *key,
                                            data: value.clone(),
                                        };
                                        Self::send_tcp_message(&mut stream, &put_msg)
                                            .await
                                            .is_ok()
                                    } else {
                                        let msg = Message::Store {
                                            id: local_id,
                                            key: *key,
                                            value: value.clone(),
                                        };
                                        matches!(
                                            Self::send_rpc_raw(&msg, node.addr, &socket).await,
                                            Ok(Message::StoreOk { .. })
                                        )
                                    };
                                    if ok {
                                        have_count += 1;
                                    }
                                }
                            }

                            if have_count < target {
                                tracing::warn!(
                                    "Value {} has only {} replicas (target {})",
                                    hex::encode(key),
                                    have_count,
                                    target,
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    /// Send an RPC and deserialize the response, using a raw socket (for spawned tasks).
    async fn send_rpc_raw(
        msg: &Message,
        target: SocketAddr,
        socket: &UdpSocket,
    ) -> anyhow::Result<Message> {
        let data = bincode::serialize(msg)?;
        let mut buf = vec![0u8; 65535];
        socket.send_to(&data, target).await?;
        let (len, from) =
            tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
        if from != target {
            anyhow::bail!("Response from unexpected address: {}", from);
        }
        Ok(bincode::deserialize(&buf[..len])?)
    }

    pub async fn find_value(&self, key: &NodeId) -> anyhow::Result<Option<Vec<u8>>> {
        {
            let s = self.store.lock().await;
            if let Some(v) = s.get(key) {
                return Ok(Some(v.clone()));
            }
        }

        let nodes = self.node_lookup(*key).await?;
        for node in &nodes {
            // Try UDP first (works for small values)
            let msg = Message::FindValue { id: self.id, key: *key };
            if let Ok(Message::FindValueOk { value: Some(v), .. }) = self.send_rpc_expect(&msg, node.addr).await {
                return Ok(Some(v));
            }
            // If UDP didn't find it, try TCP (for large values)
            if node.tcp_port != 0 {
                if let Ok(Some(v)) = self.get_chunk_tcp(node.addr, node.tcp_port, key).await {
                    return Ok(Some(v));
                }
            }
        }

        Ok(None)
    }
}
