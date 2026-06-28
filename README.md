# dstor

**Decentralized file storage over Kademlia DHT** — store files across a peer-to-peer network without any central server.

```
              CLI                 HTTP dashboard
               │                      │
          ┌────▼──────────────────────▼────┐
          │         DHT Node               │
          │   ┌──────┬──────┬────────┐     │
          │   │Routing│ Wire │  NAT   │     │
          │   └──────┴──────┴────────┘     │
          │   ┌──────┬──────┬────────┐     │
          │   │Chunks│RS EC │Crypto  │     │
          │   └──────┴──────┴────────┘     │
          └────────────────────────────────┘
```

## What problem does it solve?

Cloud storage services (Google Drive, Dropbox, etc.) own your data. Your files live on someone else's server, you pay monthly, and you lose access if they shut down or ban you.

**dstor** flips that model: your files are split into chunks, encrypted, and distributed across a peer-to-peer network. There's no company, no server to take down, no monthly bill. You own your data because the network owns it collectively.

||Cloud storage|dstor|
|---|---|---|
|Who hosts?|A company|The peers|
|Who has the key?|The provider|Only you|
|Censorship-resistant|No|Yes|
|Monthly fee|Yes|No|
|Works offline LAN|No|Yes|

## How it works (simple)

1. You store a file → it's **split into 256 KB chunks**, **encrypted** (if you set a passphrase), and **scattered** across the DHT
2. A **content hash** is returned — that's your file's address
3. Anyone with the hash can retrieve and reassemble the file
4. If some chunks are missing, **Reed-Solomon erasure coding** reconstructs them from parity data

## Quick start

```bash
# Install
cargo install dstor

# 1. Initialize
dstor init

# 2. Start your node
dstor daemon --no-http-auth

# 3. Store a file (via CLI)
dstor put myfile.txt

# 4. Or drag & drop in the browser
#    Open http://127.0.0.1:8080/ and drop a file

# 5. Retrieve
dstor get <hash> -o recovered.txt
```

### Example session

```bash
$ echo "hello dht" > hello.txt
$ dstor put hello.txt
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6

$ dstor get a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6 -o out.txt
$ cat out.txt
hello dht
```

## Features

- **Kademlia DHT** — 256-bit node IDs, iterative parallel lookups (α=3), KBucket routing (k=8)
- **Drag & drop web UI** — upload files from the browser, get download links
- **Chunking** — files split into 256 KB chunks, content-addressed by SHA-256
- **Erasure coding** — Reed-Solomon (4+2) per stripe; reconstructs from partial data
- **Encryption** — Argon2 key derivation + ChaCha20-Poly1305 per chunk
- **NAT traversal** — external address discovery + UDP hole punching through relay
- **Daemon mode** — persistent background node with Unix socket IPC
- **Watch mode** — `dstor watch <dir>` auto-stores new files via inotify
- **Docker Compose** — 3-node cluster

## Install

### From source

```bash
git clone https://github.com/iMayhem/dstore && cd dstore
cargo install --path .
```

### Docker

```bash
docker compose up -d
curl http://localhost:8081  # node1
curl http://localhost:8082  # node2
curl http://localhost:8083  # node3
```

## Commands

| Command | Description |
|---------|-------------|
| `dstor init` | Create data directories and node key |
| `dstor daemon` | Start a DHT node with HTTP dashboard |
| `dstor put <file>` | Store a file (alias: `store`) |
| `dstor get <hash>` | Retrieve a file |
| `dstor ls` | List stored files |
| `dstor rm <hash>` | Delete a file |
| `dstor watch <dir>` | Auto-store files from a directory |
| `dstor verify <hash>` | Check chunk integrity |
| `dstor repair <hash>` | Reconstruct corrupted chunks |

## Web interface

Open `http://127.0.0.1:8080/` after starting `dstor daemon`. Drag a file onto the drop zone, and it's chunked, encrypted, and stored to the DHT. You get a download link to share.

## Architecture

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
| `src/http.rs` | HTTP dashboard with upload, download, delete |

## License

MIT
