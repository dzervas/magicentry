use std::sync::Arc;

use arc_swap::ArcSwap;
use axum_test::TestServer;
use sqlx::sqlite::SqliteConnectOptions;

use crate::SESSION_COOKIE;
use crate::app_build::axum_build;
use crate::config::Config;
use crate::utils::tests::db_connect;

fn test_config(users_db_url: String) -> Config {
	let mut config = Config::default();
	config.users_sql_url = Some(users_db_url);
	config.users_sql_query_all =
		Some("SELECT username, name, email, realms FROM users".to_string());
	config.users_sql_query_email =
		Some("SELECT username, name, email, realms FROM users WHERE email = ?".to_string());
	config
}

#[tokio::test]
async fn login_uses_sql_user_store_end_to_end() -> anyhow::Result<()> {
	let temp_dir = tempfile::tempdir()?;
	let users_db_path = temp_dir.path().join("users.sqlite");
	let users_db_url = format!("sqlite://{}", users_db_path.display());
	let users_db = sqlx::SqlitePool::connect_with(
		SqliteConnectOptions::new()
			.filename(&users_db_path)
			.create_if_missing(true),
	)
	.await?;

	sqlx::query(
		"CREATE TABLE users (username TEXT NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, realms TEXT)",
	)
	.execute(&users_db)
	.await?;
	sqlx::query("INSERT INTO users (username, name, email, realms) VALUES (?, ?, ?, ?)")
		.bind("sql-valid")
		.bind("SQL Valid User")
		.bind("sql-valid@example.com")
		.bind("example,sql")
		.execute(&users_db)
		.await?;

	let config = test_config(users_db_url);
	let config_ref: Arc<ArcSwap<Config>> = Arc::new(ArcSwap::new(config.into()));
	let app_db = db_connect().await;
	let app = axum_build(app_db.clone(), config_ref, vec![], None).await;
	let server = TestServer::new(app).unwrap();

	let response = server.get("/login").await;
	assert_eq!(response.status_code(), 200);

	let response = server
		.post("/login")
		.form(&(("email", "sql-valid@example.com"),))
		.await;
	assert_eq!(response.status_code(), 200);

	let login_code: String = sqlx::query_scalar(
		"SELECT code FROM user_secrets WHERE code LIKE 'me_ll_%' ORDER BY created_at DESC LIMIT 1",
	)
	.fetch_one(&app_db)
	.await?;
	assert!(login_code.starts_with("me_ll_"));

	let stored_user: String = sqlx::query_scalar("SELECT user FROM user_secrets WHERE code = ?")
		.bind(&login_code)
		.fetch_one(&app_db)
		.await?;
	assert!(stored_user.contains("sql-valid@example.com"));
	assert!(stored_user.contains("sql-valid"));

	let response = server.get(&format!("/login/{login_code}")).await;
	assert_eq!(response.status_code(), 303);
	assert_eq!(response.header("location").to_str().unwrap(), "/");
	assert!(
		response
			.headers()
			.get_all("set-cookie")
			.iter()
			.any(|value| value
				.to_str()
				.unwrap_or_default()
				.starts_with(SESSION_COOKIE))
	);

	let remaining_login_links: i64 =
		sqlx::query_scalar("SELECT COUNT(*) FROM user_secrets WHERE code = ?")
			.bind(&login_code)
			.fetch_one(&app_db)
			.await?;
	assert_eq!(remaining_login_links, 0);

	let browser_sessions: i64 = sqlx::query_scalar(
		"SELECT COUNT(*) FROM user_secrets WHERE code LIKE 'me_bs_%' AND user = ?",
	)
	.bind(&stored_user)
	.fetch_one(&app_db)
	.await?;
	assert_eq!(browser_sessions, 1);

	Ok(())
}
