use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

fn passphrase_help() -> &'static str {
    "Encryption passphrase (also read from DSECRET env var). Omit for no encryption."
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
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
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
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
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
    },
    /// Store an entire directory recursively
    StoreDir {
        /// Path to the directory to store
        dir: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },
    /// Retrieve a stored directory
    GetDir {
        /// Root hash of the directory manifest
        root_hash: String,
        /// Output path for the reconstructed directory
        #[arg(short, long)]
        output: PathBuf,
        /// Encryption passphrase
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
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
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
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
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
        passphrase: Option<String>,
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },
    /// Serve a stored file via HTTP (starts a file server)
    Serve {
        /// Root hash of the file or directory to serve
        root_hash: String,
        /// HTTP bind address (default: 127.0.0.1:8080)
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
        /// Encryption passphrase
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
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
    },
    /// List files stored on the daemon
    List {
        /// Connect to a running daemon via Unix socket
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
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
        #[arg(short, long, env = "DSECRET", help = passphrase_help())]
        passphrase: Option<String>,
        /// Unix socket path for IPC (default: ~/.dstore/daemon.sock)
        #[arg(short = 'S', long, help = socket_help())]
        socket: Option<PathBuf>,
    },
}
