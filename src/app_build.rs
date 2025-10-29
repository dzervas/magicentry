use std::net::SocketAddr;

use actix_web::middleware::Logger;
use actix_web::{web, App, HttpServer};
use actix_web_httpauth::extractors::basic;

use axum::middleware::map_response_with_state;
use axum::routing::{get, post};
use axum::serve::Serve;
use axum::Router;
use axum_extra::routing::RouterExt as _;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;

use crate::error::error_handler;
use crate::{webauthn, AppState, CONFIG};

use crate::handle_login::handle_login;
use crate::handle_login_post::handle_login_post;
use crate::handle_logout::handle_logout;
use crate::handle_magic_link::handle_magic_link;
use crate::handle_index::handle_index;

use crate::auth_url::handle_status::handle_status;

use crate::oidc::handle_authorize::{handle_authorize_get, handle_authorize_post};
use crate::oidc::handle_discover::handle_discover;
use crate::oidc::handle_jwks::handle_jwks;
use crate::oidc::handle_token::handle_token;
use crate::oidc::handle_userinfo::handle_userinfo;

use crate::saml::handle_sso::handle_sso;
use crate::saml::handle_metadata::handle_metadata;

use crate::webauthn::handle_auth_start::handle_auth_start;
use crate::webauthn::handle_auth_finish::handle_auth_finish;
use crate::webauthn::handle_reg_start::handle_reg_start;
use crate::webauthn::handle_reg_finish::handle_reg_finish;

// We need most of the crate
#[allow(clippy::wildcard_imports)]
use crate::*;
// use crate::config::Config;
// use crate::secret::cleanup::spawn_cleanup_job;

#[allow(clippy::unwrap_used)] // Panics on boot are fine (right?)
pub async fn build(
	listen: Option<String>,
	db: Database,
	mailer: Option<SmtpTransport>,
	http_client: Option<reqwest::Client>,
) -> (Vec<SocketAddr>, actix_web::dev::Server) {
	let config = CONFIG.read().await.clone();
	let webauthn_enable = config.webauthn_enable;
	let title = config.title.clone();
	let external_url = config.external_url.clone();
	let oidc_key = oidc::init(&db).await;

	let listen = listen.unwrap_or_else(|| {
		format!("{}:{}", config.listen_host.clone(), config.listen_port)
	});

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
	.workers(if cfg!(debug_assertions) || cfg!(test) {
		1
	} else {
		std::thread::available_parallelism()
			.map(std::num::NonZero::get)
			.unwrap_or(2)
	})
	.bind(listen)
	.unwrap();


	(server.addrs(), server.run())
}

#[allow(clippy::unwrap_used)] // Panics on boot are fine (right?)
pub async fn axum_build(
	db: Database,
	config: RwLock<Arc<Config>>,
	link_senders: Vec<Arc<dyn LinkSender>>,
	router_fn: Option<fn(Router<AppState>) -> Router<AppState>>,
) -> Router {
	let config_ref = config.read().await;
	let title = config_ref.title.clone();
	let external_url = config_ref.external_url.clone();
	let key = oidc::init(&db).await;
	let webauthn = webauthn::init(&title, &external_url).unwrap();
	drop(config_ref);

	let state = AppState {
		db,
		config: Arc::new(config),
		link_senders,
		key,
		webauthn,
	};

	// TODO: Static files
	let router = Router::new()
		.route("/", get(handle_index))
		.route("/login", get(handle_login))
		.route("/login", post(handle_login_post))
		.route("/logout", get(handle_logout))
		.typed_get(handle_magic_link)

		.route("/auth-url/status", get(handle_status))

		.route("/saml/metadata", get(handle_metadata))
		.route("/saml/sso", get(handle_sso))

		.route("/.well-known/openid-configuration", get(handle_discover))
		.route("/oidc/authorize", get(handle_authorize_get))
		.route("/oidc/authorize", post(handle_authorize_post))
		.route("/oidc/jwks", get(handle_jwks))
		.route("/oidc/token", post(handle_token))
		.route("/oidc/userinfo", get(handle_userinfo))

		.route("/webauthn/auth/start", post(handle_auth_start))
		.route("/webauthn/auth/finish", post(handle_auth_finish))
		.route("/webauthn/register/start", post(handle_reg_start))
		.route("/webauthn/register/finish", post(handle_reg_finish));

	// TODO: Add a fallback route (404)

	let router_fn = router_fn.unwrap_or(|r| r);

	router_fn(router)
		.layer(map_response_with_state(state.clone(), error_handler))
		.layer(axum::middleware::from_fn_with_state(state.clone(), AppState::config_middleware))
		.layer(TraceLayer::new_for_http())
		.with_state(state)
}

pub async fn axum_run(
	listen: Option<&str>,
	db: Database,
	config: RwLock<Arc<Config>>,
	link_senders: Vec<Arc<dyn LinkSender>>,
	router_fn: Option<fn(Router<AppState>) -> Router<AppState>>,
) -> (SocketAddr, Serve<TcpListener, Router, Router>) {
	let config_listen = {
		let config_ref = config.read().await;
		format!("{}:{}", config_ref.listen_host.clone(), config_ref.listen_port)
	};

	let router = axum_build(db, config, link_senders, router_fn).await;
	let listen = listen.unwrap_or(&config_listen);
	let listener = TcpListener::bind(listen).await.unwrap();
	let server = axum::serve(listener, router);
	let local_addr = server.local_addr().unwrap();

	(local_addr, server)
}
