use config::ConfigFile;
use sqlx::sqlite::SqlitePool;
use lazy_static::lazy_static;

#[cfg(not(test))]
use lettre::transport::smtp;


pub mod config;
pub mod error;
pub mod model;
pub mod oidc;
pub mod user;
pub mod utils;
pub mod handle_index;
pub mod handle_login_page;
pub mod handle_login_action;
pub mod handle_login_link;
pub mod handle_logout;
pub mod handle_proxied;
pub mod handle_static;

pub(crate) const RANDOM_STRING_LEN: usize = 32;
pub(crate) const SESSION_COOKIE: &str = "session_id";
pub(crate) const SCOPED_SESSION_COOKIE: &str = "scoped_session_id";
pub(crate) const AUTHORIZATION_COOKIE: &str = "oidc_authorization";
pub(crate) const PROXIED_COOKIE: &str = "code";
pub(crate) const PROXIED_LOGIN_COOKIE: &str = "proxied_code";

#[cfg(not(test))]
type SmtpTransport = smtp::AsyncSmtpTransport<lettre::Tokio1Executor>;
#[cfg(not(test))]
lazy_static! {
	static ref CONFIG_FILE: String = std::env::var("CONFIG_FILE").unwrap_or("config.yaml".to_string());
}

#[cfg(test)]
type SmtpTransport = lettre::transport::stub::AsyncStubTransport;
#[cfg(test)]
lazy_static! {
	static ref CONFIG_FILE: String = "config.sample.yaml".to_string();
}

lazy_static! {
	static ref CONFIG: ConfigFile = serde_yaml::from_str::<ConfigFile>(
		&std::fs::read_to_string(CONFIG_FILE.as_str())
			.expect(format!("Unable to open config file `{:?}`", CONFIG_FILE.as_str()).as_str())
		)
		.expect(format!("Unable to parse config file `{:?}`", CONFIG_FILE.as_str()).as_str());
}

// Do not compile in tests at all as the SmtpTransport is not available
#[cfg(not(test))]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
	use actix_session::storage::CookieSessionStore;
	use actix_session::SessionMiddleware;
	use actix_web::cookie::{Key, SameSite};
	use actix_web::{web, App, HttpServer};
	use actix_web::middleware::Logger;

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


			// Auth routes
			.service(handle_index::index)
			.service(handle_login_page::login_page)
			.service(handle_login_action::login_action)
			.service(handle_login_link::login_link)
			.service(handle_logout::logout)
			.service(handle_proxied::proxied)
			.service(handle_static::static_files)
			.service(handle_static::favicon)

			// Middleware
			.wrap(Logger::default())
			.wrap(
				SessionMiddleware::builder(
					CookieSessionStore::default(),
					secret.clone()
				)
				.cookie_same_site(SameSite::Strict)
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

#[cfg(test)]
mod tests {
	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> SqlitePool {
		SqlitePool::connect(&CONFIG.database_url).await.expect("Failed to create pool.")
	}

	pub fn get_valid_user() -> User {
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == user_email { Some(u.clone()) } else { None })
			.unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}
}
