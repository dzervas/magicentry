use crate::RANDOM_STRING_LEN;

pub fn random_string() -> String {
	// TODO: Maybe tokio::task::spawn_blocking to execute this on a separate threadpool?
	let mut buffer = [0u8; RANDOM_STRING_LEN];
	rand::fill(&mut buffer);
	hex::encode(buffer)
}

#[cfg(test)]
pub mod tests {
	use std::sync::Arc;

	use arc_swap::ArcSwap;
	use axum_test::TestServer;

	use crate::app_build::axum_build;
	use crate::database::init_database;
	use crate::{Database, CONFIG};
	use crate::config::Config;
	use crate::user::User;

	use super::*;

	pub async fn db_connect() -> Database {
		// Use in-memory database for tests to avoid file system issues
		init_database("sqlite::memory:")
			.await
			.expect("Failed to initialize SQLite database")
	}

	pub async fn get_valid_user() -> User {
		Config::reload()
			.await
			.expect("Failed to reload config file");
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = {
			let config = CONFIG.read().await;
			config.users
				.iter()
				.find(|u| u.email == user_email)
				.unwrap()
				.clone()
		};

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	pub async fn server() -> TestServer {
		let db = db_connect().await;
		let config: Arc<ArcSwap<Config>> = Arc::new(ArcSwap::new(crate::CONFIG.read().await.clone()));
		let server = axum_build(db, config, vec![], None).await;
		TestServer::new(server).unwrap()
	}

	#[test]
	fn test_random_string() {
		let string1 = random_string();
		let string2 = random_string();

		assert_ne!(string1, string2);
		assert_eq!(string1.len(), RANDOM_STRING_LEN * 2);
	}
}
