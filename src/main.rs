//! epicmail: serve, check-config, import, export, selftest.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use axum::serve::ListenerExt;
use clap::{Parser, Subcommand};

use epicmail::clock::now_ms;
use epicmail::config::Config;
use epicmail::http::{self, AppState};
use epicmail::relay::Relay;
use epicmail::store::sqlite::SqliteStore;
use epicmail::store::Store;
use epicmail::{forward, logging, metrics as relay_metrics, migrate, sig};

#[derive(Parser)]
#[command(name = "epicmail", version, about = "An Epicbox relay")]
struct Cli {
    /// Configuration file (TOML).
    #[arg(long, short, global = true, default_value = "/etc/epicmail/epicmail.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the relay.
    Serve,
    /// Load and validate the configuration, then print it.
    CheckConfig,
    /// Import queued messages from a JSON Lines file (tools/export-node-pg.py or `export`).
    /// Messages already present are skipped, so it may be repeated.
    Import { file: PathBuf },
    /// Write every waiting message and queued forward as JSON Lines. Reads the store read only.
    Export {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check signatures and the store, then exit.
    Selftest,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;
    logging::init(&cfg.log);
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    match cli.cmd {
        Command::Serve => rt.block_on(serve(cfg)),
        Command::CheckConfig => {
            println!("{cfg:#?}");
            eprintln!("configuration ok");
            Ok(())
        }
        Command::Import { file } => rt.block_on(import(cfg, file)),
        Command::Export { out } => export(&cfg, out),
        Command::Selftest => rt.block_on(selftest(cfg)),
    }
}

fn open_store(cfg: &Config) -> Result<Arc<SqliteStore>> {
    if let Some(dir) = cfg.store.path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    Ok(Arc::new(SqliteStore::open(&cfg.store.path, cfg.store.readers, cfg.store.group_commit_max)?))
}

async fn serve(cfg: Config) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let handle = relay_metrics::install()?;
    let cfg = Arc::new(cfg);
    let store: Arc<dyn Store> = open_store(&cfg)?;
    store.check_writable().await.context("store is not writable")?;
    let relay = Relay::new(cfg.clone(), store);

    // Frames are small and written one at a time. With Nagle's algorithm on, a frame that follows
    // an unacknowledged one waits for the peer's delayed ACK (up to 40 ms on Linux).
    let main_listener = tokio::net::TcpListener::bind(cfg.server.listen)
        .await
        .with_context(|| format!("binding {}", cfg.server.listen))?
        .tap_io(|tcp| {
            let _ = tcp.set_nodelay(true);
        });
    let state = AppState {
        relay: relay.clone(),
        metrics: Some(handle.clone()),
        metrics_on_main: cfg.server.metrics_listen.is_none(),
    };
    let app = http::router(state).into_make_service_with_connect_info::<SocketAddr>();
    tracing::info!(
        listen = %cfg.server.listen,
        identity = %format!("{}:{}", cfg.server.domain, cfg.server.port),
        version = env!("CARGO_PKG_VERSION"),
        getversion = %cfg.protocol.getversion,
        cancel = cfg.protocol.cancel,
        mux = cfg.protocol.mux,
        http_api = cfg.http_api.enabled,
        federation = cfg.federation.enabled,
        retention_days = cfg.store.retention_days,
        max_bytes = cfg.store.max_bytes,
        "relay listening"
    );
    let mut listener = tokio::spawn(async move { axum::serve(main_listener, app).await });
    if let Some(addr) = cfg.server.metrics_listen {
        let l = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
        let app = http::metrics_router(handle.clone());
        tracing::info!(listen = %addr, "metrics listening");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(l, app).await {
                tracing::error!(error = %e, "metrics listener stopped");
            }
        });
    }
    tokio::spawn(forward::run(relay.clone()));
    tokio::spawn(housekeeping(relay.clone()));

    // If the listener ever stops, exit with an error so the supervisor restarts the relay
    // instead of leaving a process that serves nothing.
    tokio::select! {
        () = shutdown_signal() => {}
        r = &mut listener => {
            relay.draining.store(true, Ordering::Relaxed);
            let _ = relay.shutdown.send(true);
            match r {
                Ok(Ok(())) => bail!("listener stopped"),
                Ok(Err(e)) => return Err(e).context("listener failed"),
                Err(e) => bail!("listener task ended: {e}"),
            }
        }
    }
    tracing::info!(drain_seconds = cfg.server.drain_seconds, "shutting down");
    relay.draining.store(true, Ordering::Relaxed);
    let _ = relay.shutdown.send(true);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(cfg.server.drain_seconds);
    while relay.limiter.sockets_open() > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tracing::info!(open = relay.limiter.sockets_open(), "stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {}
        _ = term => {}
    }
}

/// Every 15 s: gauges. Every minute: limiter and token pruning. Every 5 minutes: expiry sweep.
/// Once a day at `store.vacuum_hour_utc`: incremental vacuum.
async fn housekeeping(relay: Arc<Relay>) {
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut shutdown = relay.shutdown.subscribe();
    let mut n: u64 = 0;
    let mut vacuumed_day: i64 = -1;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = shutdown.changed() => return,
        }
        n += 1;
        let now = now_ms();
        match relay.store.stats(now).await {
            Ok(s) => {
                metrics::gauge!("epicbox_messages_waiting").set(s.messages_waiting as f64);
                metrics::gauge!("epicbox_mailboxes_waiting").set(s.mailboxes_waiting as f64);
                metrics::gauge!("epicbox_oldest_waiting_seconds").set(s.oldest_waiting_ms as f64 / 1000.0);
                metrics::gauge!("epicbox_oldest_unoffered_seconds").set(s.oldest_unoffered_ms as f64 / 1000.0);
                metrics::gauge!("epicbox_forwards_waiting").set(s.forwards_waiting as f64);
                metrics::gauge!("epicbox_oldest_forward_seconds").set(s.oldest_forward_ms as f64 / 1000.0);
                metrics::gauge!("epicbox_tombstones").set(s.tombstones as f64);
                metrics::gauge!("epicbox_db_bytes").set(s.db_bytes as f64);
                metrics::gauge!("epicbox_store_used_bytes").set(s.used_bytes as f64);
                *relay.last_stats.lock() = Some(s);
            }
            Err(e) => epicmail::sampled!(error, error = %e, "store stats failed"),
        }
        let (mailboxes, mux, _) = relay.registry.counts();
        metrics::gauge!("epicbox_listening_mailboxes").set(mailboxes as f64);
        metrics::gauge!("epicbox_mux_holders").set(mux as f64);
        metrics::gauge!("epicbox_mux_tokens").set(relay.tokens_live() as f64);
        metrics::gauge!("epicbox_http_waiting_pulls").set(f64::from(relay.pull_waiters.waiting()));
        metrics::gauge!("epicbox_store_ok").set(if relay.store_ok.load(Ordering::Relaxed) { 1.0 } else { 0.0 });

        if n.is_multiple_of(4) {
            relay.limiter.prune();
            relay.prune_tokens();
        }
        if n % 20 == 1 {
            match relay.store.sweep(now, relay.retention_ms()).await {
                Ok(s) => {
                    relay.store_ok.store(true, Ordering::Relaxed);
                    let removed = s.messages_expired
                        + s.forwards_expired
                        + s.tombstones_expired
                        + s.challenges_expired
                        + s.txlinks_expired;
                    if removed > 0 {
                        tracing::info!(?s, "expiry sweep");
                    } else {
                        tracing::debug!("expiry sweep: nothing expired");
                    }
                }
                Err(e) => {
                    relay.store_ok.store(false, Ordering::Relaxed);
                    tracing::error!(error = %e, "expiry sweep failed");
                }
            }
        }
        let day = now / 86_400_000;
        let hour = (now / 3_600_000) % 24;
        if hour == i64::from(relay.cfg.store.vacuum_hour_utc) && day != vacuumed_day {
            vacuumed_day = day;
            if let Err(e) = relay.store.vacuum().await {
                tracing::error!(error = %e, "vacuum failed");
            }
        }
    }
}

async fn import(cfg: Config, file: PathBuf) -> Result<()> {
    let store = open_store(&cfg)?;
    let f = std::fs::File::open(&file).with_context(|| format!("opening {}", file.display()))?;
    let stats = migrate::import_jsonl(store.as_ref(), &cfg, std::io::BufReader::new(f), now_ms()).await?;
    println!("{}", serde_json::to_string_pretty(&stats)?);
    Ok(())
}

fn export(cfg: &Config, out: Option<PathBuf>) -> Result<()> {
    let stats = match out {
        Some(p) => {
            let f = std::fs::File::create(&p).with_context(|| format!("creating {}", p.display()))?;
            let mut w = std::io::BufWriter::new(f);
            let s = migrate::export_jsonl(&cfg.store.path, &mut w)?;
            std::io::Write::flush(&mut w)?;
            s
        }
        None => {
            let stdout = std::io::stdout();
            let mut w = std::io::BufWriter::new(stdout.lock());
            let s = migrate::export_jsonl(&cfg.store.path, &mut w)?;
            std::io::Write::flush(&mut w)?;
            s
        }
    };
    eprintln!("{}", serde_json::to_string(&stats)?);
    Ok(())
}

async fn selftest(cfg: Config) -> Result<()> {
    let secret = secp256k1::SecretKey::from_secret_bytes(rand::random())?;
    let pk = secp256k1::PublicKey::from_secret_key(&secret);
    let s = sig::sign(&secret, "selftest");
    if sig::verify_with_key(&pk, "selftest", &s).is_err() || sig::verify_with_key(&pk, "other", &s).is_ok() {
        bail!("signature check failed");
    }
    println!("signatures: ok");
    let store = open_store(&cfg)?;
    store.check_writable().await.context("store write check")?;
    println!("store: ok ({})", cfg.store.path.display());
    Ok(())
}
