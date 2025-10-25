#![forbid(unsafe_code)]
use magicentry::config::Config;
use magicentry::secret::cleanup::spawn_cleanup_job;
pub use magicentry::*;

use lettre::transport::smtp;
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

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

// Do not compile in tests at all as the SmtpTransport is not available
#[allow(clippy::unwrap_used)] // Panics on boot are fine (right?)
#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
	// TODO: Add a log checker during test that checks for secrets and panics if it finds any
	init_tracing();

	#[cfg(debug_assertions)]
	tracing::warn!("Running in debug mode, all magic links will be printed to the console.");

	Config::reload()
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

	let _config_watcher = config::Config::watch();
	spawn_cleanup_job(db.clone());

	#[cfg(feature = "kube")]
	tokio::select! {
		r = server => r,
		k = magicentry::config_kube::watch() => Err(std::io::Error::other(format!("Kube watcher failed: {k:?}"))),
	}

	#[cfg(not(feature = "kube"))]
	server.await
}
