use std::sync::Arc;

use arc_swap::ArcSwap;
use lettre::transport::smtp;
use magicentry::secret::cleanup::spawn_cleanup_job;
use tracing::info;

use magicentry::app_build::axum_run;
use magicentry::config::Config;
use magicentry::database::init_database;
use magicentry::{init_tracing, SmtpTransport, CONFIG};

// Issues:
// - Test webauthn
// - Finish the styling
// - Maybe browser session middleware?
// - Test hot reload with hurl (actual file editing)
// - Test kube e2e
// - Per-type token endpoint to split them (PCRE/code/etc.)
// - HTML & style the email (and the http?)
// - SAML deflate can be a tokio middleware (already in tower-http)
// - End up on concrete error-handling (strings or enum or whatever)
// - Cache authurl status?
// - Use &'static AppState and `&*Box::leak(Box::new(state))` to avoid cloning (since the state will never get freed) and remove Arc from config and link senders
// - Clean architecture
// - Have a "server" section for stuff that require a restart
// - Handle restarts

#[tokio::main]
async fn main() {
	init_tracing(None);
	Config::reload()
		.await
		.expect("Failed to reload config file");
	let database_url = CONFIG.read().await.database_url.clone();

	let config: Arc<ArcSwap<Config>> = Arc::new(ArcSwap::new(crate::CONFIG.read().await.clone()));
	let db = init_database(&database_url)
		.await
		.expect("Failed to initialize SQLite database");

	let mut link_senders: Vec<Arc<dyn magicentry::LinkSender>> = vec![];

	let config_inst = config.load();
	if config_inst.smtp_enable {
		let smtp_inst: SmtpTransport = smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&config_inst.smtp_url)
			.expect("Failed to create mailer - is the `smtp_url` correct?")
			.pool_config(smtp::PoolConfig::new())
			.build();
		link_senders.push(Arc::new(smtp_inst));
	}
	if config_inst.request_enable {
		link_senders.push(Arc::new(reqwest::Client::new()));
	}
	drop(config_inst);

	let (addr, server) = axum_run(None, db.clone(), config, link_senders, None).await;

	let _watcer = Config::watch();
	spawn_cleanup_job(db.clone());

	info!("Server running on http://{addr}");

	#[cfg(feature = "kube")]
	tokio::select! {
		r = server => r,
		k = magicentry::config_kube::watch() => Err(std::io::Error::other(format!("Kube watcher failed: {k:?}"))),
	}.unwrap();

	#[cfg(not(feature = "kube"))]
	server.await.unwrap();
}
