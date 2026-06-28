use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

fn passphrase_help() -> &'static str {
    "Encryption passphrase (also read from DSTORE_PASSPHRASE env var or DSTORE_PASSPHRASE_FILE path). Omit for no encryption."
}

fn socket_help() -> &'static str {
    "Daemon Unix socket path (default: ~/.dstore/daemon.sock)"
}

#[derive(Parser)]
#[command(name = "dstore", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Split a file into encrypted chunks; store locally and optionally publish to DHT
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
    /// Reassemble a file from local encrypted chunks or fetch from DHT
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
    Delete {
        /// Root hash of the file to delete
        root_hash: String,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },
    /// Garbage collect orphaned chunks not referenced by any stored file
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
    /// Serve a stored file via HTTP (starts a file server)
    Serve {
        /// Root hash of the file or directory to serve
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
    /// List files stored on the daemon
    List {
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },
    /// Mount a stored file via FUSE (requires libfuse3-dev at build time)
    #[cfg(feature = "fuse")]
    Mount {
        /// Root hash of the file to mount
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
        /// Encryption passphrase (required for HTTP download of encrypted files)
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
}
