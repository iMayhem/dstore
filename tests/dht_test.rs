use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;

use dstor::net::dht::DhtNode;
use dstor::net::protocol::NodeId;
use dstor::net::routing::RoutingTable;
use sha2::Digest;

fn make_signing_key() -> ed25519_dalek::SigningKey {
    let sk_bytes = rand::random::<[u8; 32]>();
    ed25519_dalek::SigningKey::from_bytes(&sk_bytes)
}

fn random_node_id() -> NodeId {
    rand::random()
}

fn get_local_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

#[tokio::test]
async fn test_bootstrap_and_lookup() {
    let node_a = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();

    let node_b = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let addr_b = node_b.local_addr().unwrap();

    // Spawn node B in background
    let b_handle = tokio::spawn(async move {
        node_b.run().await.unwrap();
    });

    // Give node B a moment to start
    sleep(Duration::from_millis(100)).await;

    // Node A bootstraps with B
    node_a.bootstrap(addr_b).await.unwrap();

    // Verify A knows about B
    let rt_a = node_a.routing.lock().await;
    assert!(rt_a.contains(&node_a.id)); // self
    // After bootstrap+lookup, B should be in A's routing table
    let known_b = rt_a.all_nodes().iter().any(|n| n.addr == addr_b);
    assert!(known_b, "Node A should know about Node B after bootstrap");

    drop(rt_a);

    // Test store/find value
    let key: NodeId = random_node_id();
    let value = b"hello from dstore!".to_vec();

    // Store via A — this should reach B
    node_a.store_value(key, value.clone()).await.unwrap();

    // Find via B — we can't easily query B since it's in the spawned task
    // But we can check that A has it locally
    let found = node_a.find_value(&key).await.unwrap();
    assert_eq!(found, Some(value));

    // Clean up
    b_handle.abort();
}

#[tokio::test]
async fn test_store_and_retrieve_via_dht() {
    // Node B = always-on daemon
    let node_b = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let addr_b = node_b.local_addr().unwrap();
    let b_handle = tokio::spawn(async move {
        node_b.run().await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    // Node A = store
    let node_a = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_a.bootstrap(addr_b).await.unwrap();
    sleep(Duration::from_millis(200)).await;

    // Store a file through A
    let file_data = b"Hello from DHT store test!".to_vec();
    let tmpfile = std::env::temp_dir().join("dht_test_store.bin");
    std::fs::write(&tmpfile, &file_data).unwrap();
    let (chunks, manifest) = dstor::chunk::chunk_file(&tmpfile).unwrap();
    std::fs::remove_file(&tmpfile).ok();

    // Publish manifest
    let manifest_json = serde_json::to_string(&manifest).unwrap();
    let root_hash = hex::encode(sha2::Sha256::digest(manifest_json.as_bytes()));
    let root_key = hex_to_id(&root_hash);
    node_a.store_value(root_key, manifest_json.as_bytes().to_vec()).await.unwrap();

    // Publish each chunk
    for (i, chunk_data) in chunks.iter().enumerate() {
        let info = &manifest.chunks[i];
        let chunk_key = hex_to_id(&info.hash);
        node_a.store_value(chunk_key, chunk_data.clone()).await.unwrap();
    }

    // Node C = retrieve (fresh node, bootstraps with B)
    let node_c = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_c.bootstrap(addr_b).await.unwrap();
    sleep(Duration::from_millis(200)).await;

    // Fetch manifest
    let fetched_manifest_bytes = node_c.find_value(&root_key).await.unwrap().unwrap();
    let fetched_manifest: dstor::chunk::Manifest =
        serde_json::from_slice(&fetched_manifest_bytes).unwrap();

    assert_eq!(fetched_manifest.file_name, manifest.file_name);
    assert_eq!(fetched_manifest.total_chunks, manifest.total_chunks);

    // Fetch each chunk
    let mut fetched_data = Vec::new();
    for info in &fetched_manifest.chunks {
        let chunk_key = hex_to_id(&info.hash);
        let chunk_data = node_c.find_value(&chunk_key).await.unwrap().unwrap();
        fetched_data.extend_from_slice(&chunk_data);
    }

    assert_eq!(fetched_data, file_data, "Retrieved file must match original");

    b_handle.abort();
}

fn hex_to_id(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap();
    let mut id = [0u8; 32];
    id.copy_from_slice(&bytes);
    id
}

#[tokio::test]
async fn test_routing_table_closest() {
    let local_id = random_node_id();
    let mut rt = RoutingTable::new(local_id);

    let node1_id = random_node_id();
    let node1_addr: SocketAddr = "127.0.0.1:8001".parse().unwrap();
    rt.insert(node1_id, node1_addr, 0);

    let node2_id = random_node_id();
    let node2_addr: SocketAddr = "127.0.0.1:8002".parse().unwrap();
    rt.insert(node2_id, node2_addr, 0);

    let target = random_node_id();
    let closest = rt.closest(&target, 2);
    assert_eq!(closest.len(), 2);

    // Both inserted nodes should be found
    let addrs: Vec<_> = closest.iter().map(|n| n.addr).collect();
    assert!(addrs.contains(&node1_addr));
    assert!(addrs.contains(&node2_addr));
}

#[tokio::test]
async fn test_external_address_discovery() {
    let relay = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let relay_handle = tokio::spawn(async move {
        relay.run().await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let node = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let external = node.discover_addr(relay_addr).await.unwrap();
    assert_eq!(external, node.local_addr().unwrap(),
        "On localhost, external address should match local address");

    // Single peer confirmation doesn't reach minimum vote threshold (3),
    // so external_addr() returns None until more peers confirm.
    let stored = node.external_addr().await;
    assert_eq!(stored, None, "Single peer cannot confirm external address");

    relay_handle.abort();
}

#[tokio::test]
async fn test_hole_punch_coordination() {
    // Set up three nodes: relay (R), target (T), requester (A)
    let relay = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let relay_handle = tokio::spawn(async move {
        relay.run().await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let target = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let target_id = target.id;
    let target_handle = tokio::spawn(async move {
        target.run().await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let requester = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();

    // Requester asks relay to punch to target
    requester
        .hole_punch(relay_addr, target_id, target_addr)
        .await
        .unwrap();

    relay_handle.abort();
    target_handle.abort();
}

#[tokio::test]
async fn test_large_value_tcp_transfer() {
    let node_b = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let addr_b = node_b.local_addr().unwrap();
    let b_handle = tokio::spawn(async move {
        node_b.run().await.unwrap();
    });
    sleep(Duration::from_millis(100)).await;

    let node_a = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_a.bootstrap(addr_b).await.unwrap();
    sleep(Duration::from_millis(200)).await;

    // Create a value larger than MAX_DATAGRAM_SIZE (4096) to force TCP path
    let large_value: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
    let key: NodeId = random_node_id();

    node_a.store_value(key, large_value.clone()).await.unwrap();

    // Retrieve from a fresh node C
    let node_c = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_c.bootstrap(addr_b).await.unwrap();
    sleep(Duration::from_millis(200)).await;

    let found = node_c.find_value(&key).await.unwrap();
    assert_eq!(found, Some(large_value), "Large value must match after TCP transfer");

    b_handle.abort();
}

#[tokio::test]
async fn test_ec_file_store_get_over_dht() {
    // Bootstrap node
    let bootstrap = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    let bootstrap_addr = bootstrap.local_addr().unwrap();
    let bootstrap_handle = tokio::spawn(async move {
        bootstrap.run().await.unwrap();
    });
    sleep(Duration::from_millis(200)).await;

    // Create a file large enough to produce multiple chunks and trigger EC (4+2)
    let file_data: Vec<u8> = (0..(500 * 1024)).map(|i| (i % 256) as u8).collect();
    let tmpfile = std::env::temp_dir().join("dht_ec_test_original.bin");
    std::fs::write(&tmpfile, &file_data).unwrap();

    // Node A = store the file (erasure coded, no encryption for simplicity)
    let node_a = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_a.bootstrap(bootstrap_addr).await.unwrap();
    sleep(Duration::from_millis(300)).await;

    let (plaintext_chunks, mut manifest) = dstor::chunk::chunk_file(&tmpfile).unwrap();
    let total_data = plaintext_chunks.len();
    let (data_shards, parity_shards) = dstor::erasure::choose_config(total_data);
    manifest.data_shards = data_shards;
    manifest.parity_shards = parity_shards;

    let mut all_chunks: Vec<(dstor::chunk::ChunkInfo, Vec<u8>)> = Vec::new();

    if parity_shards > 0 {
        let stripes = plaintext_chunks.chunks(data_shards);
        for (stripe_idx, stripe_data) in stripes.enumerate() {
            let mut stripe_input = stripe_data.to_vec();
            while stripe_input.len() < data_shards {
                stripe_input.push(vec![0u8; 0]);
            }
            let encoded = dstor::erasure::encode_stripe(&stripe_input, parity_shards)
                .expect("EC encode failed");
            for (shard_idx, shard_pt) in encoded.iter().enumerate() {
                let is_parity = shard_idx >= data_shards;
                let hash = hex::encode(sha2::Sha256::digest(shard_pt));
                let (chunk_index, orig_size) = if is_parity {
                    ((shard_idx - data_shards) as u32, 0u32)
                } else {
                    let file_idx = stripe_idx * data_shards + shard_idx;
                    let s = if file_idx < total_data { manifest.chunks[file_idx].size } else { 0 };
                    (shard_idx as u32, s)
                };
                let info = dstor::chunk::ChunkInfo {
                    hash: hash.clone(),
                    index: chunk_index,
                    size: orig_size,
                    nonce: None,
                    is_parity,
                    stripe_index: stripe_idx as u32,
                };
                all_chunks.push((info, shard_pt.clone()));
            }
        }
    }
    manifest.chunks = all_chunks.iter().map(|(info, _)| info.clone()).collect();
    manifest.total_chunks = all_chunks.len() as u32;

    // Publish each chunk to the DHT
    for (info, data) in &all_chunks {
        let key = hex_to_id(&info.hash);
        node_a.store_value(key, data.clone()).await.unwrap();
    }

    // Publish manifest to the DHT
    let manifest_json = serde_json::to_string(&manifest).unwrap();
    let root_hash = hex::encode(sha2::Sha256::digest(manifest_json.as_bytes()));
    let root_key = hex_to_id(&root_hash);
    node_a.store_value(root_key, manifest_json.as_bytes().to_vec()).await.unwrap();
    tracing::info!("Stored file root: {}", root_hash);

    // Node B = retrieve (fresh node, bootstraps with bootstrap)
    let node_b = DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap();
    node_b.bootstrap(bootstrap_addr).await.unwrap();
    sleep(Duration::from_millis(300)).await;

    // Fetch manifest from DHT
    let fetched_manifest_bytes = node_b.find_value(&root_key).await.unwrap()
        .expect("Manifest not found on DHT");
    let fetched_manifest: dstor::chunk::Manifest =
        serde_json::from_slice(&fetched_manifest_bytes).unwrap();
    assert_eq!(fetched_manifest.data_shards, manifest.data_shards);
    assert_eq!(fetched_manifest.total_chunks, manifest.total_chunks);

    // Fetch all chunks from DHT
    let mut fetched_chunks: Vec<(dstor::chunk::ChunkInfo, Vec<u8>)> = Vec::new();
    for info in &fetched_manifest.chunks {
        let key = hex_to_id(&info.hash);
        let chunk_data = node_b.find_value(&key).await.unwrap()
            .unwrap_or_else(|| panic!("Chunk {} not found on DHT", info.hash));
        // Verify integrity
        let actual_hash = hex::encode(sha2::Sha256::digest(&chunk_data));
        assert_eq!(actual_hash, info.hash, "Hash mismatch for chunk {}", info.hash);
        fetched_chunks.push((info.clone(), chunk_data));
    }

    // Reassemble using EC (replicate ec_reassemble logic)
    let tmp_store = dstor::store::ChunkStore::new(std::env::temp_dir().join("dht_ec_test_store"));
    for (info, data) in &fetched_chunks {
        tmp_store.store_chunk(&info.hash, data).unwrap();
    }

    let output = std::env::temp_dir().join("dht_ec_test_output.bin");

    // Group by stripe
    let mut stripe_map: std::collections::HashMap<u32, Vec<&dstor::chunk::ChunkInfo>> =
        std::collections::HashMap::new();
    for info in &fetched_manifest.chunks {
        stripe_map.entry(info.stripe_index).or_default().push(info);
    }
    let total_stripes = stripe_map.len();

    let mut out_file = std::fs::File::create(&output).unwrap();
    for stripe_idx in 0..total_stripes as u32 {
        let infos = stripe_map.remove(&stripe_idx).unwrap_or_default();
        let total_shards = (data_shards + parity_shards) as usize;
        let mut available: Vec<Option<Vec<u8>>> = (0..total_shards).map(|_| None).collect();
        let mut original_sizes = vec![0usize; data_shards as usize];

        for info in &infos {
            let pos = if info.is_parity {
                data_shards as usize + info.index as usize
            } else {
                info.index as usize
            };
            if pos >= total_shards {
                continue;
            }
            if let Some(data) = tmp_store.load_chunk(&info.hash).unwrap() {
                if !info.is_parity {
                    original_sizes[pos] = info.size as usize;
                }
                available[pos] = Some(data);
            }
        }

        let present = available.iter().filter(|s| s.is_some()).count();
        assert!(present >= data_shards as usize,
            "Stripe {}: only {}/{} shards available", stripe_idx, present, total_shards);

        let reconstructed = dstor::erasure::decode_stripe(
            &available, data_shards as usize, parity_shards as usize, &original_sizes,
        ).expect("RS reconstruction failed");

        use std::io::Write;
        for chunk_data in &reconstructed {
            if !chunk_data.is_empty() {
                out_file.write_all(chunk_data).unwrap();
            }
        }
    }
    drop(out_file);

    // Verify integrity
    let output_data = std::fs::read(&output).unwrap();
    assert_eq!(output_data.len(), file_data.len(),
        "Output size {} != original size {}", output_data.len(), file_data.len());
    assert_eq!(output_data, file_data, "Retrieved file must match original");

    // Cleanup
    std::fs::remove_file(&tmpfile).ok();
    std::fs::remove_file(&output).ok();
    std::fs::remove_dir_all(std::env::temp_dir().join("dht_ec_test_store")).ok();
    bootstrap_handle.abort();
}

#[tokio::test]
async fn test_ec_partial_recovery() {
    // Test EC recovery directly via the erasure module
    let data_shards = 4;
    let parity_shards = 2;

    // Create 4 data shards with different sizes
    let data: Vec<Vec<u8>> = vec![
        (0..262144).map(|_| rand::random::<u8>()).collect(),
        (0..262144).map(|_| rand::random::<u8>()).collect(),
        (0..262144).map(|_| rand::random::<u8>()).collect(),
        (0..131072).map(|_| rand::random::<u8>()).collect(),
    ];
    let original_sizes: Vec<usize> = data.iter().map(|d| d.len()).collect();

    // Encode
    let encoded = dstor::erasure::encode_stripe(&data, parity_shards).unwrap();
    assert_eq!(encoded.len(), data_shards + parity_shards);

    // Simulate 2 missing shards (indices 0 and 3)
    let mut available: Vec<Option<Vec<u8>>> = (0..data_shards + parity_shards).map(|_| None).collect();
    available[1] = Some(encoded[1].clone());
    available[2] = Some(encoded[2].clone());
    available[4] = Some(encoded[4].clone()); // parity 0
    available[5] = Some(encoded[5].clone()); // parity 1

    // Reconstruct
    let reconstructed = dstor::erasure::decode_stripe(
        &available, data_shards, parity_shards, &original_sizes,
    ).expect("RS recovery failed");

    assert_eq!(reconstructed.len(), data_shards);
    for (i, chunk) in reconstructed.iter().enumerate() {
        assert_eq!(chunk.len(), data[i].len(),
            "Shard {} size mismatch: {} vs {}", i, chunk.len(), data[i].len());
        assert_eq!(&chunk[..], &data[i][..], "Shard {} data mismatch", i);
    }
}

#[tokio::test]
async fn test_node_id_generation() {
    let id1 = random_node_id();
    let id2 = random_node_id();
    assert_ne!(id1, id2, "Two generated IDs must be different");
    assert_eq!(id1.len(), 32);
    assert_eq!(id2.len(), 32);
}

#[tokio::test]
async fn test_http_download() {
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Create test file
    let file_data: Vec<u8> = (0..8192).map(|_| rand::random::<u8>()).collect();
    let tmpdir = std::env::temp_dir().join("dht_http_test");
    let _ = std::fs::remove_dir_all(&tmpdir);
    std::fs::create_dir_all(&tmpdir).unwrap();
    let tmpfile = tmpdir.join("test_data.bin");
    std::fs::write(&tmpfile, &file_data).unwrap();
    let store_dir = tmpdir.join("store");
    let chunk_dir = store_dir.join("chunks");
    std::fs::create_dir_all(&chunk_dir).unwrap();

    // Chunk the file
    let (chunks_data, manifest) = dstor::chunk::chunk_file(&tmpfile).unwrap();
    let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
    let manifest_key = {
        let hash = sha2::Sha256::digest(&manifest_bytes);
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    };

    // Store chunks locally
    let chunk_store = dstor::store::ChunkStore::new(chunk_dir);
    for chunk in &chunks_data {
        let hash = hex::encode(sha2::Sha256::digest(chunk));
        chunk_store.store_chunk(&hash, chunk).unwrap();
    }

    // Add file to index
    let mut file_index = dstor::store::FileIndex::load(&store_dir);
    file_index.files.push(dstor::store::FileRecord {
        name: tmpfile.file_name().unwrap().to_string_lossy().to_string(),
        root_hash: hex::encode(manifest_key),
        size: file_data.len() as u64,
        stored_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        chunk_count: chunks_data.len() as u32,
    });
    file_index.save(&store_dir).unwrap();
    drop(chunk_store);

    // Create DHT node and add all keys to its store (so find_value works locally)
    let node = Arc::new(DhtNode::new(get_local_addr(), make_signing_key()).await.unwrap());

    // Store manifest in DHT
    node.store_value(manifest_key, manifest_bytes).await.unwrap();

    // Store each chunk in DHT
    for chunk in &chunks_data {
        let chunk_hash = sha2::Sha256::digest(chunk);
        let mut chunk_key = [0u8; 32];
        chunk_key.copy_from_slice(&chunk_hash);
        node.store_value(chunk_key, chunk.clone()).await.unwrap();
    }

    // Start HTTP server on random port
    let http_state = Arc::new(dstor::http::HttpState {
        node: node.clone(),
        store_dir: store_dir.clone(),
        encryption_key: None,
        start_time: std::time::Instant::now(),
        auth_token: None,
        tls_config: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = listener.local_addr().unwrap();
    let state_clone = http_state.clone();

    // Accept one connection and delegate to handle_connection
    let accept_handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        dstor::http::handle_connection(&mut stream, state_clone).await.ok();
    });

    sleep(Duration::from_millis(100)).await;

    // Make HTTP request
    let mut tcp = tokio::net::TcpStream::connect(http_addr).await.unwrap();
    let request = format!(
        "GET /download/{} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        hex::encode(manifest_key)
    );
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();

    // Parse HTTP response body
    let status_line = response.splitn(2, |&b| b == b'\n').next()
        .and_then(|s| std::str::from_utf8(s).ok())
        .unwrap_or("");
    assert!(status_line.contains("200"), "HTTP status not 200: {}", status_line);

    let body_start = response.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);
    let downloaded = &response[body_start..];

    assert_eq!(downloaded, &file_data, "Downloaded data must match original");

    // Cleanup
    std::fs::remove_dir_all(&tmpdir).ok();
    accept_handle.abort();
}
