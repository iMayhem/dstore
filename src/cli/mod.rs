use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

fn passphrase_help() -> &'static str {
    "Encryption passphrase (use DSTORE_PASSPHRASE env var or DSTORE_PASSPHRASE_FILE instead of this flag for security)"
}

fn socket_help() -> &'static str {
    "Daemon Unix socket path (default: ~/.dstore/daemon.sock)"
}

/// Decentralized file storage over Kademlia DHT
///
/// Store, retrieve, and share files across a peer-to-peer network
/// with encryption, erasure coding, and NAT traversal.
///
/// QUICK START:
///   dstore init              First-time setup
///   dstore daemon            Start your node
///   dstore put myfile.txt    Store a file
///   dstore ls                List stored files
///   dstore get <hash> out    Retrieve a file
///
/// EXAMPLES:
///   dstore put secret.pdf --passphrase "hunter2"
///   dstore get abc123def... recovered.pdf
///   dstore daemon --bootstrap 192.168.1.5:7890
///   dstore watch ~/share --passphrase "hunter2"
#[derive(Parser)]
#[command(name = "dstore", version, verbatim_doc_comment)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// One-time setup: create data directories, generate node keys, print info
    Init {
        /// Data directory (default: ~/.dstore)
        #[arg(short, long)]
        dir: Option<PathBuf>,
    },

    /// Start a DHT node (daemon mode)
    Daemon {
        /// Address to listen on (default: 0.0.0.0:0 for random port)
        #[arg(short, long, default_value = "0.0.0.0:0")]
        addr: SocketAddr,
        /// Optional bootstrap node address
        #[arg(short, long)]
        bootstrap: Option<SocketAddr>,
        /// HTTP dashboard bind address (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        http_port: String,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Unix socket path for IPC (default: ~/.dstore/daemon.sock)
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
        /// Disable HTTP auth token (not recommended)
        #[arg(long)]
        no_http_auth: bool,
        /// Disable TLS (not recommended)
        #[arg(long)]
        no_tls: bool,
    },

    /// Store a file (alias: put)
    #[command(alias = "put")]
    Store {
        /// Path to the file to store
        file: PathBuf,
        /// Output directory for chunks (default: ./dstore_data)
        #[arg(short, long, default_value = "./dstore_data")]
        out: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// DHT listen address (optional; omit for local-only)
        #[arg(short, long)]
        addr: Option<SocketAddr>,
        /// DHT bootstrap node address
        #[arg(short, long)]
        bootstrap: Option<SocketAddr>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Retrieve a file from DHT or local store
    Get {
        /// Root hash of the file to retrieve
        root_hash: String,
        /// Output path for the reassembled file
        #[arg(short, long)]
        output: PathBuf,
        /// Local chunk store directory (default: ./dstore_data)
        #[arg(short, long, default_value = "./dstore_data")]
        store: Option<PathBuf>,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// DHT listen address (optional; omit for local-only)
        #[arg(short, long)]
        addr: Option<SocketAddr>,
        /// DHT bootstrap node address
        #[arg(short, long)]
        bootstrap: Option<SocketAddr>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Store an entire directory recursively
    StoreDir {
        /// Path to the directory to store
        dir: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Retrieve a stored directory
    GetDir {
        /// Root hash of the directory manifest
        root_hash: String,
        /// Output path for the reconstructed directory
        #[arg(short, long)]
        output: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Delete a file from the local store and file index
    #[command(alias = "rm")]
    Delete {
        /// Root hash of the file to delete
        root_hash: String,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },

    /// Garbage collect orphaned chunks
    Gc {
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },

    /// Watch a directory and auto-store new files
    Watch {
        /// Path to the directory to watch
        dir: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Maximum file size in bytes to auto-store (default: no limit)
        #[arg(long)]
        max_file_size: Option<u64>,
        /// Follow symlinks (default: reject)
        #[arg(long)]
        follow_symlinks: bool,
    },

    /// Verify integrity of all chunks for a stored file
    Verify {
        /// Root hash of the file to verify
        root_hash: String,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },

    /// Repair corrupted chunks using erasure coding parity
    Repair {
        /// Root hash of the file to repair
        root_hash: String,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Serve a stored file via HTTP
    Serve {
        /// Root hash to serve
        root_hash: String,
        /// HTTP bind address (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// DHT listen address (optional; omit for local-only)
        #[arg(short, long)]
        addr: Option<SocketAddr>,
        /// DHT bootstrap node address
        #[arg(short, long)]
        bootstrap: Option<SocketAddr>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },

    /// Show daemon status and connected peers
    Status {
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },

    /// List stored files (alias: ls)
    #[command(alias = "ls")]
    List {
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },

    /// Mount a stored file via FUSE (requires libfuse3-dev at build time)
    #[cfg(feature = "fuse")]
    Mount {
        /// Root hash to mount
        root_hash: String,
        /// Mount point directory
        #[arg(short, long)]
        mount_point: PathBuf,
        /// DHT listen address
        #[arg(short, long)]
        addr: SocketAddr,
        /// DHT bootstrap node address
        #[arg(short, long)]
        bootstrap: Option<SocketAddr>,
        /// Encryption passphrase
        #[arg(short, long, env = "DSTORE_PASSPHRASE", help = passphrase_help())]
        passphrase: Option<String>,
        /// Argon2 memory cost in KiB (default: 192)
        #[arg(long, default_value = "192")]
        argon2_mem_kib: u32,
        /// Argon2 time cost (iterations, default: 2)
        #[arg(long, default_value = "2")]
        argon2_iters: u32,
        /// Argon2 parallelism (lanes, default: 1)
        #[arg(long, default_value = "1")]
        argon2_lanes: u32,
    },
}
