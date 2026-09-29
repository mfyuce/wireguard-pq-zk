//! wg-zk-daemon: userspace half of the wgzk handshake, protocol revision R1
//! (`docs/protocol-r1.md`).
//!
//! Subcommands:
//! - `run` (default, alias `daemon`): the daemon. `WGZK_MODE` selects the role:
//!   client ([`client`], Section 5) or gateway ([`gateway`], Section 6). Configuration comes
//!   from the environment and `.env` ([`settings`], see `.env.example`).
//! - `derive-addr <base64 public key>`: print the tunnel address of Section 3.5.
//! - `new-connection --iface <name>`: fresh session key and address on an interface
//!   ([`sessionkey`]).
//!
//! The cargo feature `fault-injection` (off by default) adds the module `fault`, with which a
//! client misbehaves on purpose for the negative acceptance tests.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod addr;
mod client;
mod ctbuf;
#[cfg(feature = "fault-injection")]
mod fault;
mod gateway;
mod keylock;
mod mlkem;
mod mlkem_channel;
mod netlink;
mod peers;
mod replay;
mod sessionkey;
mod settings;
mod tool;
mod wgnl;
mod zk;

use settings::{ProcessEnv, Role};

#[derive(Parser)]
#[command(name = "wg-zk-daemon", about = "wgzk handshake daemon (protocol revision R1)")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon (default); the role comes from WGZK_MODE.
    #[command(alias = "daemon")]
    Run,
    /// Print the tunnel address derived from a base64 WireGuard public key.
    DeriveAddr {
        /// Session public key S_c, base64 as printed by `wg`.
        public_key: String,
    },
    /// Generate a fresh session key for an interface and assign its derived address.
    NewConnection {
        /// WireGuard interface of the connection.
        #[arg(long)]
        iface: String,
    },
}

/// Load `.env` if present. A parse error is reported without the offending line, which may
/// hold a key.
fn load_dotenv() {
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(dotenvy::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(dotenvy::Error::LineParse(_, pos)) => eprintln!("[daemon] .env: parse error at position {pos}"),
        Err(dotenvy::Error::Io(e)) => eprintln!("[daemon] .env: {e}"),
        Err(_) => eprintln!("[daemon] .env could not be loaded"),
    }
}

fn derive_addr(public_key: &str) -> Result<()> {
    let key: [u8; 32] = STANDARD
        .decode(public_key.trim())
        .map_err(|_| anyhow!("public key is not valid base64"))?
        .try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))?;
    let prefix = settings::addr_prefix(&ProcessEnv)?;
    println!("{}", addr::derive_addr(&prefix, &key));
    Ok(())
}

async fn new_connection(iface: &str) -> Result<()> {
    let prefix = settings::addr_prefix(&ProcessEnv)?;
    let (public, addr) = sessionkey::new_connection(iface, &prefix).await?;
    println!("public_key={}", STANDARD.encode(public));
    println!("address={addr}");
    Ok(())
}

async fn run() -> Result<()> {
    eprintln!("[daemon] Starting");
    // Process-wide rustls provider; the TLS configurations and the certificate verifier use it.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("a rustls crypto provider is already installed"))?;
    let env = ProcessEnv;
    let role = settings::role(&env)?;
    let daemon = async {
        match role {
            Role::Client => client::run(settings::client_config(&env)?).await,
            Role::Gateway => gateway::run(settings::gateway_config(&env)?).await,
        }
    };
    tokio::select! {
        r = daemon => r,
        _ = tokio::signal::ctrl_c() => {
            eprintln!("[daemon] shutdown");
            Ok(())
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    load_dotenv();
    let result = match cli.command.unwrap_or(Command::Run) {
        Command::Run => run().await,
        Command::DeriveAddr { public_key } => derive_addr(&public_key),
        Command::NewConnection { iface } => new_connection(&iface).await,
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[daemon] error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
