use magicentry::config::{ConfigFile, ConfigKV, ConfigKeys};
pub use magicentry::*;

use actix_session::storage::CookieSessionStore;
use actix_session::SessionMiddleware;
use actix_web::cookie::{Key, SameSite};
use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use actix_web_httpauth::extractors::basic;
use lettre::transport::smtp;
use reindeer::Entity;
#[cfg(feature = "kube")]
use tokio::select;

// Do not compile in tests at all as the SmtpTransport is not available
#[actix_web::main]
pub async fn main() -> std::io::Result<()> {
	env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

	#[cfg(debug_assertions)]
	log::warn!("Running in debug mode, all magic links will be printed to the console.");

	ConfigFile::reload()
		.await
		.expect("Failed to load config file");

	let config = CONFIG.read().await;
	let cookie_duration = config
		.session_duration
		.clone()
		.to_std()
		.expect("Couldn't parse session_duration");
	let webauthn_enable = config.webauthn_enable;
	let listen_host = config.listen_host.clone();
	let listen_port = config.listen_port;
	let title = config.title.clone();
	let external_url = config.external_url.clone();

	let db = reindeer::open(config.database_url.clone().as_str())
		.expect("Failed to open reindeer database.");
	user_secret::register(&db).unwrap();
	config::ConfigKV::register(&db).expect("Failed to register config_kv entity");
	token::register_token_kind(&db).expect("Failed to register token kinds");
	webauthn::store::PasskeyStore::register(&db).expect("Failed to register passkey store");

	let secret = if let Ok(Some(secret_kv)) = ConfigKV::get(&ConfigKeys::Secret, &db) {
		let secret = secret_kv
			.value
			.expect("Failed to load secret from database");
		let master = hex::decode(secret)
			.expect("Failed to decode secret - is something wrong with the database?");
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		ConfigKV::set(ConfigKeys::Secret, Some(master), &db)
			.expect("Unable to set secret in the database");

		key
	};

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

	// OIDC setup
	let oidc_key = oidc::init(&db).await;
	drop(config);

	let server = HttpServer::new(move || {
		let mut app = App::new()
			// Data
			.app_data(web::Data::new(db.clone()))
			.app_data(web::Data::new(mailer.clone()))
			.app_data(web::Data::new(http_client.clone()))
			.app_data(basic::Config::default().realm("MagicEntry"))

			.default_service(web::route().to(error::not_found))

			// Auth routes
			.service(handle_index::index)
			.service(handle_login_page::login_page)
			.service(handle_login_action::login_action)
			.service(handle_login_link::login_link)
			.service(handle_logout::logout)
			.service(handle_static::static_files)
			.service(handle_static::favicon)

			// Auth URL routes
			.service(auth_url::handle_status::status)

			// SAML routes
			.service(saml::handle_metadata::metadata)
			.service(saml::handle_sso::sso)

			// OIDC routes
			.app_data(web::Data::new(oidc_key.clone()))
			.service(oidc::handle_discover::discover)
			.service(oidc::handle_discover::discover_preflight)
			.service(oidc::handle_authorize::authorize_get)
			.service(oidc::handle_authorize::authorize_post)
			.service(oidc::handle_token::token)
			.service(oidc::handle_token::token_preflight)
			.service(oidc::handle_jwks::jwks)
			.service(oidc::handle_userinfo::userinfo)
			// Handle oauth discovery too
			.service(web::redirect("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration").permanent())

			// Middleware
			.wrap(Logger::default())
			.wrap(
				SessionMiddleware::builder(
					CookieSessionStore::default(),
					secret.clone()
				)
				// TODO: Handle secure & http only cookies (config)
				// .cookie_http_only(true)
				// .cookie_secure(false)
				.cookie_same_site(SameSite::Lax)
				.session_lifecycle(
					actix_session::config::PersistentSession::default()
						.session_ttl(
							actix_web::cookie::time::Duration::try_from(cookie_duration)
							.expect("Couldn't set session_ttl - something is wrong with session_duration"))
				)
				.build());

		if webauthn_enable {
			let webauthn = webauthn::init(title.clone(), external_url.clone())
				.expect("Failed to create webauthn object");

			app = app
				.app_data(web::Data::new(webauthn))
				.service(webauthn::handle_reg_start::reg_start)
				.service(webauthn::handle_reg_finish::reg_finish)
				.service(webauthn::handle_auth_start::auth_start)
				.service(webauthn::handle_auth_finish::auth_finish);
		}

		app
	})
	.bind(format!("{}:{}", listen_host, listen_port))
	.unwrap()
	.run();

	let _config_watcher = config::ConfigFile::watch();

	#[cfg(feature = "kube")]
	{
		let kube_watcher = config_kube::watch();

		select! {
			r = server => r,
			k = kube_watcher => Err(std::io::Error::new(std::io::ErrorKind::Other, format!("Kube watcher failed: {:?}", k))),
		}
	}

	#[cfg(not(feature = "kube"))]
	{
		server.await
	}
}
