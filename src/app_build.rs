use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use actix_web_httpauth::extractors::basic;

// We need most of the crate
#[allow(clippy::wildcard_imports)]
use crate::*;
// use crate::config::ConfigFile;
// use crate::secret::cleanup::spawn_cleanup_job;

#[allow(clippy::unwrap_used)] // Panics on boot are fine (right?)
pub async fn build(
	listen: Option<String>,
	db: Database,
	mailer: Option<SmtpTransport>,
	http_client: Option<reqwest::Client>,
) -> actix_web::dev::Server {
	let config = CONFIG.read().await;
	let webauthn_enable = config.webauthn_enable;
	let title = config.title.clone();
	let external_url = config.external_url.clone();
	let oidc_key = oidc::init(&db).await;

	let listen = listen.unwrap_or_else(|| {
		format!("{}:{}", config.listen_host.clone(), config.listen_port)
	});
	drop(config);

	HttpServer::new(move || {
		let mut app = App::new()
			// Data
			.app_data(web::Data::new(db.clone()))
			.app_data(web::Data::new(mailer.clone()))
			.app_data(web::Data::new(http_client.clone()))
			.app_data(basic::Config::default().realm("MagicEntry"))

			.default_service(web::route().to(error::not_found))

			// Auth routes
			.service(handle_index::index)
			.service(handle_login::login)
			.service(handle_login_post::login_post)
			.service(handle_magic_link::magic_link)
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
			.wrap(Logger::default());

		if webauthn_enable {
			let webauthn = webauthn::init(&title.clone(), &external_url.clone())
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
	.workers(if cfg!(debug_assertions) || cfg!(test) || cfg!(feature = "e2e-test") {
		1
	} else {
		std::thread::available_parallelism()
			.map(std::num::NonZero::get)
			.unwrap_or(2)
	})
	.bind(listen)
	.unwrap()
	.run()
}
