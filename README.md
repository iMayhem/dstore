# dstore

Decentralized file storage over Kademlia DHT with erasure coding, encryption, and NAT traversal.

```
dstore store myfile.txt
> a1b2c3d4e5f6...

dstore get a1b2c3d4e5f6... -o myfile.txt

dstore daemon --bootstrap 192.168.1.5:10001
```

## Features

- **Kademlia DHT** — 256-bit node IDs, iterative parallel lookups (α=3), KBucket routing (k=8)
- **Chunking** — files split into 256 KB chunks, content-addressed by SHA-256 hash
- **Erasure coding** — Reed-Solomon (reed-solomon-erasure) per stripe: (1+1) for 1 chunk, (2+1) for 2–3, (4+2) for 4+; reconstructs from partial data
- **Encryption at rest** — Argon2 key derivation + ChaCha20-Poly1305 per chunk; all peers assumed adversarial
- **NAT traversal** — external address discovery + UDP hole punching through relay
- **TCP data transfer** — chunks >4 KB transferred over TCP (UDP port + 1)
- **Daemon mode** — persistent background node with Unix socket IPC
- **HTTP dashboard** — browser UI at `http://localhost:8080` with file listing & download
- **Anti-entropy** — periodic replica checking, value re-publishing, bucket refresh
- **Directory store/get** — recursive directory walk, file-by-file with root DirManifest
- **Integrity self-repair** — `dstore verify` (SHA-256 check) + `dstore repair` (RS decode → re-encrypt → overwrite)
- **Watch mode** — `dstore watch <dir>` auto-stores new files via inotify
- **Delete & GC** — `dstore delete` removes from index + chunks; `dstore gc` orphans cleanup
- **Docker Compose** — 3-node cluster with HTTP dashboards

## Install

### From source

```bash
git clone <url> && cd dstore
cargo install --path .
```

Requires Rust 1.75+. No system dependencies beyond what `cargo` fetches.

> FUSE mount is not available on systems without `libfuse3-dev`. See [FUSE section](#fuse-mount) for alternatives.

### Docker

```bash
docker compose up -d
curl http://localhost:8081  # node1 dashboard
curl http://localhost:8082  # node2
curl http://localhost:8083  # node3
```

## Usage

### Store a file

```bash
# Local-only (no DHT)
dstore store myfile.txt

# With encryption
dstore store myfile.txt --passphrase "hunter2"

# Publish to DHT
dstore store myfile.txt --addr 0.0.0.0:0 --bootstrap 192.168.1.5:10001

# Via daemon
dstore store myfile.txt --socket ~/.dstore/daemon.sock
```

### Retrieve a file

```bash
dstore get a1b2c3d4e5f6... -o output.bin
dstore get a1b2c3d4e5f6... -o output.bin --passphrase "hunter2"
```

### Directory

```bash
dstore store-dir ./photos --passphrase "hunter2"
> d4e5f6a1b2c3...

dstore get-dir d4e5f6a1b2c3... -o ./restored_photos
```

### Daemon mode

```bash
# Start background node
dstore daemon --bootstrap 192.168.1.5:10001

# With HTTP dashboard + encryption for downloads
dstore daemon --passphrase "hunter2" --http-port 127.0.0.1:8080

# Default socket: ~/.dstore/daemon.sock
# Default HTTP:  http://127.0.0.1:8080
```

### HTTP file serving

```bash
# Connect to a running daemon and print download URL
dstore serve a1b2c3d4e5f6...

# Start standalone HTTP file server
dstore serve a1b2c3d4e5f6... \
  --addr 0.0.0.0:0 \
  --bootstrap 192.168.1.5:10001 \
  --passphrase "hunter2" \
  --bind 127.0.0.1:8080
```

### Other commands

```bash
dstore list                      # list stored files
dstore verify a1b2c...           # check chunk integrity
dstore repair a1b2c...           # repair corrupted chunks via RS
dstore delete a1b2c...           # delete file + chunks
dstore gc                        # remove orphaned chunks
dstore watch ./incoming          # auto-store files in directory
```

## Architecture

```
┌──────────────────────────────────────────────────┐
│                    dstore                         │
│  ┌─────────┐  ┌──────────┐  ┌─────────────────┐ │
│  │   CLI    │  │  Daemon  │  │  HTTP Dashboard  │ │
│  │ (clap)   │  │ (IPC)    │  │  (file browser)  │ │
│  └────┬────┘  └────┬─────┘  └────────┬────────┘ │
│       │             │                 │           │
│  ┌────▼─────────────▼─────────────────▼───────┐  │
│  │            DHT Node (Kademlia)              │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │  │ Routing  │  │   Wire   │  │   NAT    │  │  │
│  │  │  Table   │  │ Protocol │  │ Traversal│  │  │
│  │  └──────────┘  └──────────┘  └──────────┘  │  │
│  └─────────────────────────────────────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌─────────────────┐ │
│  │  Chunk   │  │  Erasure │  │    Crypto        │ │
│  │  Store   │  │  Coding  │  │ (ChaCha20+Argon2)│ │
│  └──────────┘  └──────────┘  └─────────────────┘ │
└──────────────────────────────────────────────────┘
```

### Wire protocol (UDP, <4 KB)

| Message | Payload |
|---------|---------|
| Ping/Pong | NodeId, addr, tcp_port, external_addr |
| FindNode | target_id → closest k nodes |
| FindValue | key → value or closest nodes |
| Store | key, value |
| GetChunk | hash → TCP chunk transfer |

All messages are bincode-serialized over UDP. Values >4 KB fall through to TCP (port = UDP port + 1).

### Erasure coding

Files are grouped into stripes of up to 4 data shards + 2 parity shards. Each shard is individually encrypted with a unique nonce. Missing shards are reconstructed via Reed-Solomon on retrieval — files remain recoverable even when several chunks are unavailable.

### Encryption

```
passphrase → Argon2id → 32-byte key
                              ↓
plaintext → ChaCha20-Poly1305 → [nonce][ciphertext]
                                    ↓
                              SHA-256 → content address
```

Every chunk gets a fresh random nonce. Ciphertext is hashed for integrity. Parity shards are encrypted with their own nonces.

## FUSE mount

`dstore mount` is not available on systems without `libfuse3-dev` (the `fuser` crate requires the C library headers at build time).

**Alternative**: use the HTTP file server and mount it with FUSE:

```bash
# Start the daemon
dstore daemon --passphrase "hunter2"

# Mount via httpfs (install fuse-http first)
httpfs http://localhost:8080/download/<root-hash> /mnt/dstore

# Or just use curl/wget
curl -O http://localhost:8080/download/<root-hash>
```

## Development

```bash
# Build
cargo build

# Test (9 integration tests)
cargo test

# Lint
cargo clippy

# Run with tracing
RUST_LOG=info cargo run -- daemon --bootstrap <addr>
```

### Project structure

| Path | Description |
|------|-------------|
| `src/main.rs` | CLI, daemon, IPC handlers, EC pipelines |
| `src/cli/mod.rs` | Command-line argument definitions |
| `src/chunk/mod.rs` | File chunking, Manifest, DirEntry |
| `src/store/mod.rs` | ChunkStore on disk, FileIndex |
| `src/crypto/` | Argon2, ChaCha20-Poly1305, Ed25519 keys |
| `src/erasure/mod.rs` | Reed-Solomon encode/decode |
| `src/net/dht.rs` | DHT node, Kademlia, TCP, NAT |
| `src/net/routing.rs` | RoutingTable, KBucket |
| `src/net/protocol.rs` | Wire message types |
| `src/ipc.rs` | Unix socket daemon IPC |
| `src/http.rs` | HTTP dashboard + file download |

## License

MIT
