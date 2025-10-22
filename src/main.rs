#![forbid(unsafe_code)]
use magicentry::config::ConfigFile;
use magicentry::secret::cleanup::spawn_cleanup_job;
pub use magicentry::*;

use lettre::transport::smtp;

// Do not compile in tests at all as the SmtpTransport is not available
#[allow(clippy::unwrap_used)] // Panics on boot are fine (right?)
#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
	// TODO: Add a log checker during test that checks for secrets and panics if it finds any
	env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));


	#[cfg(feature = "e2e-test")]
	log::warn!("Running in E2E Tests mode, all magic links will written to disk in the `.link.txt` file.");

	#[cfg(debug_assertions)]
	log::warn!("Running in debug mode, all magic links will be printed to the console.");

	ConfigFile::reload()
		.await
		.expect("Failed to load config file");

	let config = CONFIG.read().await;
	let db = database::init_database(&config.database_url)
		.await
		.expect("Failed to initialize SQLite database");
	// Mailer setup
	let mailer: Option<SmtpTransport> = if config.smtp_enable {
		Some(
			smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&config.smtp_url)
				.expect("Failed to create mailer - is the `smtp_url` correct?")
				.pool_config(smtp::PoolConfig::new())
				.build(),
		)
	} else {
		None
	};
	// HTTP client setup
	let http_client = if config.request_enable {
		Some(reqwest::Client::new())
	} else {
		None
	};
	drop(config);

	let (_addrs, server) = crate::app_build::build(None, db.clone(), mailer, http_client).await;

	let _config_watcher = config::ConfigFile::watch();
	spawn_cleanup_job(db.clone());

	#[cfg(feature = "kube")]
	tokio::select! {
		r = server => r,
		k = magicentry::config_kube::watch() => Err(std::io::Error::other(format!("Kube watcher failed: {k:?}"))),
	}

	#[cfg(not(feature = "kube"))]
	server.await
}
