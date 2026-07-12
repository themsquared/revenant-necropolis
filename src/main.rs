//! Standalone Necropolis server for deployment (Fly.io / VPS / the mini). Lean
//! — depends only on revenant-net, not the whole harness — so the container
//! image stays small. Binds 0.0.0.0 for containers. Configured by env:
//!   PORT              listen port (default 8080)
//!   NECROPOLIS_DB     ledger path (default /data/necropolis.db — a Fly volume)
//!   NECROPOLIS_PEERS  comma-separated peer Necropolis URLs to federate from
//!   NECROPOLIS_SYNC_SECS  federation interval in seconds (default 30)

mod server;
mod accounts;
mod email;

use std::sync::{Arc, Mutex};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080);
    let db = std::env::var("NECROPOLIS_DB").unwrap_or_else(|_| "/data/necropolis.db".to_string());

    let dir = crate::server::Directory::open(&db)?;
    tracing::info!("necropolis ledger '{db}' verified: {} entries", dir.ledger_len()?);
    let shared = Arc::new(Mutex::new(dir));

    // Optional federation: mirror one or more peer Necropolises, re-verifying
    // every entry against our own head before it is written.
    let peers: Vec<String> = std::env::var("NECROPOLIS_PEERS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !peers.is_empty() {
        let secs: u64 = std::env::var("NECROPOLIS_SYNC_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(30);
        tracing::info!("federating from {} peer(s) every {secs}s: {}", peers.len(), peers.join(", "));
        tokio::spawn(crate::server::federate(shared.clone(), peers, Duration::from_secs(secs)));
    }

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    crate::server::serve(addr, shared).await
}
