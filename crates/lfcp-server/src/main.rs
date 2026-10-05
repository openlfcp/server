//! `lfcp-server`: run the reference server until SIGINT or SIGTERM, or, with
//! `--health-check`, probe a running one (exit status 0 when healthy).

use std::process::ExitCode;
use std::sync::Arc;

use lfcp_server::config::Config;
use lfcp_server::identity::FileIdentity;
use lfcp_server::server::Server;
use lfcp_server::store::Store;

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let health_check = args.first().map(String::as_str) == Some("--health-check");
    if health_check {
        args.remove(0);
    }
    let config = match Config::from_args(args) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("lfcp-server: {error}");
            return ExitCode::from(2);
        }
    };
    if health_check {
        return if lfcp_server::http::probe(config.bind, std::time::Duration::from_secs(3)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }
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
        let (admin, setup_code) = match lfcp_server::admin::Admin::open(
            server.store().clone(),
            server.server_id(),
            server.config(),
            std::sync::Arc::new(lfcp_server::rng::OsRandom),
            lfcp_server::admin::SETUP_TTL,
        )
        .await
        {
            Ok(opened) => opened,
            Err(error) => {
                tracing::error!(%error, "cannot open the admin surface");
                return ExitCode::FAILURE;
            }
        };
        // The one place the setup code is shown: stdout, once, never the
        // log (WIRE-01 §92). Only its hash is stored.
        if let Some(code) = setup_code {
            println!(
                "\nAdmin pairing code:\n\n    {}\n\nOpen /setup and pair an LFCP Principal as server administrator.\nThe code expires in {} minutes; restart the server for a new one.\n",
                code.expose(),
                lfcp_server::admin::SETUP_TTL.as_secs() / 60
            );
        }
        let sessions = lfcp_server::session::Lfcp::new(server.store().clone(), server.config())
            .with_hosting(admin.hosting());
        server.with_admin(admin).run(sessions, shutdown_signal()).await;
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
