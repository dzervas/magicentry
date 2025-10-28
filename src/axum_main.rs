use axum::middleware::map_response_with_state;
use axum::routing::{get, post};
use axum::Router;
use axum_extra::routing::RouterExt as _;

use magicentry::{webauthn, AppState, CONFIG};

use magicentry::handle_login::handle_login;
use magicentry::handle_login_post::handle_login_post;
use magicentry::handle_logout::handle_logout;
use magicentry::handle_magic_link::handle_magic_link;
use magicentry::handle_index::handle_index;

use magicentry::auth_url::handle_status::handle_status;

use magicentry::oidc::handle_authorize::{handle_authorize_get, handle_authorize_post};
use magicentry::oidc::handle_discover::handle_discover;
use magicentry::oidc::handle_jwks::handle_jwks;
use magicentry::oidc::handle_token::handle_token;
use magicentry::oidc::handle_userinfo::handle_userinfo;

use magicentry::saml::handle_sso::handle_sso;
use magicentry::saml::handle_metadata::handle_metadata;

use magicentry::webauthn::handle_auth_start::handle_auth_start;
use magicentry::webauthn::handle_auth_finish::handle_auth_finish;
use magicentry::webauthn::handle_reg_start::handle_reg_start;
use magicentry::webauthn::handle_reg_finish::handle_reg_finish;

// Issues:
// - Add a middleware/extractor that checks the origin of the request?
// - Maybe browser session middleware?
// - App builder
// - Test migration & replace main
// - Remove actix-web
// - Per-type token endpoint to split them (PCRE/code/etc.)
// - HTML & style the email (and the http?)
// - SAML deflate can be a tokio middleware (already in tower-http)
// - Clone the config on each request - maybe using FromRef<OuterState> for AppState where OuterState has access to the lock
// - Cache authurl status?
// - Use &'static AppState and `&*Box::leak(Box::new(state))` to avoid cloning (since the state will never get freed) and remove Arc from config and link senders

#[tokio::main]
async fn main() {
	let db = magicentry::database::init_database("sqlite::memory:")
		.await
		.expect("Failed to initialize SQLite database");
	let config = CONFIG.read().await.clone();
	let title = config.title.clone();
	let external_url = config.external_url.clone();

	let state = AppState {
		db,
		config,
		link_senders: vec![],
		// XXX: Well, yea
		key: jsonwebtoken::EncodingKey::from_secret(b"secret"),
		webauthn: webauthn::init(&title, &external_url).unwrap(),
	};

	// Set up the router with the typed path
	let app = Router::new()
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
		.route("/webauthn/register/finish", post(handle_reg_finish))

		.layer(map_response_with_state(state.clone(), magicentry::error::error_handler))
		.with_state(state);

	// Run the server
	let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
		.await
		.unwrap();

	println!("Server running on http://0.0.0.0:3000");
	axum::serve(listener, app).await.unwrap();
}
