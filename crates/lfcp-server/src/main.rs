//! `lfcp-server`: run the reference server until SIGINT or SIGTERM.

use std::process::ExitCode;
use std::sync::Arc;

use lfcp_server::config::Config;
use lfcp_server::identity::FileIdentity;
use lfcp_server::server::Server;
use lfcp_server::store::Store;

fn main() -> ExitCode {
    let config = match Config::from_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lfcp-server: {error}");
            return ExitCode::from(2);
        }
    };
    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .init();

    let identity = match FileIdentity::load_or_create(&config.state_dir) {
        Ok(identity) => identity,
        Err(error) => {
            tracing::error!(%error, "cannot load the server identity");
            return ExitCode::FAILURE;
        }
    };
    let store = match Store::open(&config.state_dir) {
        Ok(store) => Arc::new(store),
        Err(error) => {
            tracing::error!(%error, "cannot open the store");
            return ExitCode::FAILURE;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "cannot start the runtime");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(async {
        let server = match Server::bind(config, Arc::new(identity), store).await {
            Ok(server) => server,
            Err(error) => {
                tracing::error!(%error, "cannot bind");
                return ExitCode::FAILURE;
            }
        };
        tracing::info!(
            addr = %server.local_addr().map(|a| a.to_string()).unwrap_or_default(),
            server_id = %server.server_id().to_hex(),
            "listening"
        );
        server.run(shutdown_signal()).await;
        ExitCode::SUCCESS
    })
}

/// SIGINT (Ctrl-C) or, on Unix, SIGTERM.
async fn shutdown_signal() {
    let interrupt = async {
        if tokio::signal::ctrl_c().await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
}
