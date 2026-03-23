use std::sync::Arc;

use arc_swap::ArcSwap;
use magicentry::secret::cleanup::spawn_cleanup_job;
use tracing::info;

use magicentry::app_build::axum_run;
use magicentry::config::Config;
use magicentry::database::init_database;
use magicentry::{CONFIG_FILE, init_tracing};

// Issues:
// - Make webauthn not require an email?
// - Test webauthn
// - Test kube e2e
// - Bring back the benchmark (maybe axum-test instead of hurl)
// - Clean architecture
// - Per-type token endpoint to split them (PCRE/code/etc.)
// - HTML & style the email (and the http?)
// - SAML deflate can be a tokio middleware (already in tower-http)
// - Maybe browser session middleware?
// - End up on concrete error-handling (strings or enum or whatever)
// - Cache authurl status?
// - Use &'static AppState and `&*Box::leak(Box::new(state))` to avoid cloning (since the state will never get freed) and remove Arc from config and link senders
// - Have a "server" section for stuff that require a restart
// - Handle restarts
// - Split up the page styling madness (and use p.class-name instead of p class="class-name")

#[tokio::main]
async fn main() {
	init_tracing(None);
	tracing::info!(
		"MagicEntry Enterprise Edition v{}",
		env!("CARGO_PKG_VERSION")
	);

	let config = Config::reload_from_path(&CONFIG_FILE)
		.await
		.expect("Failed to reload config file");
	let database_url = config.database_url.clone();
	let link_senders = config.get_link_senders();
	let user_store = config
		.get_user_store()
		.expect("Could not construct a valid user store");

	let config: Arc<ArcSwap<Config>> = Arc::new(ArcSwap::new(config.into()));
	let db = init_database(&database_url)
		.await
		.expect("Failed to initialize SQLite database");

	let (_addr, server) = axum_run(
		None,
		db.clone(),
		config.clone(),
		link_senders,
		user_store,
		None,
	)
	.await;

	let _watcer = Config::watch(CONFIG_FILE.as_str(), config.clone());
	spawn_cleanup_job(db.clone());

	#[cfg(feature = "kube")]
	tokio::select! {
		r = server => r,
		k = magicentry::config_kube::watch(config) => Err(std::io::Error::other(format!("Kube watcher failed: {k:?}"))),
	}.unwrap();

	#[cfg(not(feature = "kube"))]
	server.await.unwrap();
}
