use axum::Router;
use axum_extra::routing::RouterExt as _;

use magicentry::CONFIG;
use magicentry::handle_magic_link::{handle_magic_link, AppState};

#[tokio::main]
async fn main() {
	let db = magicentry::database::init_database("sqlite::memory:")
		.await
		.expect("Failed to initialize SQLite database");

	// Set up the router with the typed path
	let app = Router::new()
		.typed_get(handle_magic_link)
		.with_state(AppState {
			db,
			config: CONFIG.read().await.clone(),
			mailer: None,
			http_client: None,
		});

	// Run the server
	let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
		.await
		.unwrap();

	println!("Server running on http://0.0.0.0:3000");
	axum::serve(listener, app).await.unwrap();
}
