use axum::middleware::map_response_with_state;
use axum::routing::{get, post};
use axum::Router;
use axum_extra::routing::RouterExt as _;

use magicentry::{CONFIG, AppState};
use magicentry::handle_login::handle_login;
use magicentry::handle_login_post::handle_login_post;
use magicentry::handle_logout::handle_logout;
use magicentry::handle_magic_link::handle_magic_link;
use magicentry::handle_index::handle_index;

// Issues:
// - Implement the rest of the endpoints
// - Add a middleware/extractor that checks the origin of the request - there's a feature flag in axum?
// - Maybe browser session middleware?
// - App builder
// - Test migration & replace main
// - Remove actix-web
// - Per-type token endpoint to split them (PCRE/code/etc.)
// - HTML & style the email (and the http?)
// - SAML deflate can be a tokio middleware (already in tower-http)
// - Cache authurl status?

#[tokio::main]
async fn main() {
	let db = magicentry::database::init_database("sqlite::memory:")
		.await
		.expect("Failed to initialize SQLite database");

	let state = AppState {
		db,
		config: CONFIG.read().await.clone(),
		link_senders: vec![],
	};

	// Set up the router with the typed path
	let app = Router::new()
		.route("/", get(handle_index))
		.route("/login", get(handle_login))
		.route("/login", post(handle_login_post))
		.route("/logout", get(handle_logout))
		.typed_get(handle_magic_link)
		.layer(map_response_with_state(state.clone(), magicentry::error::error_handler))
		.with_state(state);

	// Run the server
	let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
		.await
		.unwrap();

	println!("Server running on http://0.0.0.0:3000");
	axum::serve(listener, app).await.unwrap();
}
