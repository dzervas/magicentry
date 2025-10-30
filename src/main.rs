use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use magicentry::CONFIG;
use magicentry::database::init_database;
use magicentry::config::Config;
use magicentry::app_build::axum_run;

fn init_tracing() {
	let log_level = std::env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
	let log_format = std::env::var("LOG_FORMAT").unwrap_or_else(|_| "compact".to_string());
	let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&log_level));

	match log_format.as_str() {
		"json" => {
			tracing_subscriber::registry()
				.with(filter)
				.with(fmt::layer().json())
				.init();
		}
		"pretty" => {
			tracing_subscriber::registry()
				.with(filter)
				.with(fmt::layer().pretty())
				.init();
		}
		_ => {
			tracing_subscriber::registry()
				.with(filter)
				.with(fmt::layer().compact())
				.init();
		}
	}
}

// Issues:
// - Fix the fucking config
// - Maybe browser session middleware?
// - Per-type token endpoint to split them (PCRE/code/etc.)
// - HTML & style the email (and the http?)
// - SAML deflate can be a tokio middleware (already in tower-http)
// - Clone the config on each request - maybe using FromRef<OuterState> for AppState where OuterState has access to the lock
// - End up on concrete error-handling (strings or enum or whatever)
// - Cache authurl status?
// - Use &'static AppState and `&*Box::leak(Box::new(state))` to avoid cloning (since the state will never get freed) and remove Arc from config and link senders

#[tokio::main]
async fn main() {
	init_tracing();
	Config::reload().await.expect("Failed to reload config file");
	let database_url = CONFIG.read().await.database_url.clone();

	let config: Arc<RwLock<Arc<Config>>> = Arc::new(RwLock::new(crate::CONFIG.read().await.clone()));
	let db = init_database(&database_url)
		.await
		.expect("Failed to initialize SQLite database");

	// TODO: Add link senders
	// TODO: Have a "server" section for stuff that require a restart
	// TODO: Handle restarts

	let (addr, server) = axum_run(Some("127.0.0.1:8080"), db, config, vec![], None).await;

	info!("Server running on http://{addr}");
	server.await.unwrap();
}
