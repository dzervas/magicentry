pub use magicentry::*;

use lettre::transport::smtp;
use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::{Key, SameSite};
use actix_web::{web, App, HttpServer};
use actix_web::middleware::Logger;
use sqlx::sqlite::SqlitePool;

// Do not compile in tests at all as the SmtpTransport is not available
#[actix_web::main]
async fn main() -> std::io::Result<()> {
	env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

	#[cfg(debug_assertions)]
	log::warn!("Running in debug mode, all magic links will be printed to the console.");

	// Database setup
	let db = SqlitePool::connect(&CONFIG.database_url).await.expect("Failed to create sqlite pool.");
	sqlx::migrate!().run(&db).await.expect("Failed to run database migrations.");
	let secret = if let Some(secret) = config::ConfigKV::get(&db, "secret").await {
		let master = hex::decode(secret).expect("Failed to decode secret - is something wrong with the database?");
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		config::ConfigKV::set(&db, "secret", &master).await.unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		key
	};

	// Mailer setup
	let mailer: Option<SmtpTransport> = if CONFIG.smtp_enable {
		Some(smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&CONFIG.smtp_url)
			.expect("Failed to create mailer - is the `smtp_url` correct?")
			.pool_config(smtp::PoolConfig::new())
			.build())
	} else {
		None
	};

	// HTTP client setup
	let http_client = if CONFIG.request_enable {
		Some(reqwest::Client::new())
	} else {
		None
	};

	// OIDC setup
	let oidc_key = oidc::init(&db).await;

	HttpServer::new(move || {
		let app = App::new()
			// Data
			.app_data(web::Data::new(db.clone()))
			.app_data(web::Data::new(mailer.clone()))
			.app_data(web::Data::new(http_client.clone()))

			.default_service(web::route().to(error::not_found))

			// Auth routes
			.service(handle_index::index)
			.service(handle_login_page::login_page)
			.service(handle_login_action::login_action)
			.service(handle_login_link::login_link)
			.service(handle_logout::logout)
			.service(handle_static::static_files)
			.service(handle_static::favicon)

			.service(auth_url::handle_status::status)
			.service(auth_url::handle_response::response)

			// Middleware
			.wrap(Logger::default())
			.wrap(
				SessionMiddleware::builder(
					CookieSessionStore::default(),
					secret.clone()
				)
				.cookie_same_site(SameSite::Lax)
				// .cookie_path(CONFIG.path_prefix.clone())
				.session_lifecycle(
					actix_session::config::PersistentSession::default()
						.session_ttl(
							actix_web::cookie::time::Duration::try_from(
								CONFIG
								.session_duration
								.to_std()
								.expect("Couldn't parse session_duration")
							)
							.expect("Couldn't set session_ttl - something is wrong with session_duration"))
				)
				.build());

		// OIDC routes
		if CONFIG.oidc_enable {
			app.app_data(web::Data::new(oidc_key.clone()))
				.service(oidc::handle_discover::discover)
				.service(oidc::handle_authorize::authorize_get)
				.service(oidc::handle_authorize::authorize_post)
				.service(oidc::handle_token::token)
				.service(oidc::handle_jwks::jwks)
				.service(oidc::handle_userinfo::userinfo)
		} else {
			app
		}
	})
	.bind(format!("{}:{}", CONFIG.listen_host, CONFIG.listen_port))?
	.run()
	.await
}
