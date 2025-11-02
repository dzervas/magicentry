use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::info;

use magicentry::{init_tracing, CONFIG};
use magicentry::database::init_database;
use magicentry::config::Config;
use magicentry::app_build::axum_run;

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
	init_tracing(None);
	Config::reload().await.expect("Failed to reload config file");
	let database_url = CONFIG.read().await.database_url.clone();

	let config: Arc<ArcSwap<Config>> = Arc::new(ArcSwap::new(crate::CONFIG.read().await.clone()));
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
