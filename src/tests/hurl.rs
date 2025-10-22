use std::net::SocketAddr;

use rand::Rng;

use crate::*;

pub async fn app_server() -> (actix_web::dev::Server, Vec<SocketAddr>, sqlx::SqlitePool) {
    ConfigFile::reload().await.unwrap();
	let db = database::init_database("sqlite::memory:").await.unwrap();

	let (addrs, server) = app_build::build(
		Some("127.0.0.1:0".to_string()),
		db.clone(),
		None,
		None,
	).await;

	(server, addrs, db)
}

pub async fn insert_login_link(db: &sqlx::SqlitePool, index: usize, rand: &str, redirect: &str) {
	sqlx::query!(
		"INSERT INTO user_secrets (code, secret_type, expires_at, metadata) VALUES (?, ?, datetime('now', '+1 hour'), ?)",
		format!("me_ll_{rand}{index}"),
		crate::user_secret::UserSecretType::LoginLink,
	)
	.execute(db)
	.await
	.unwrap();
}

pub async fn run_test(hurl_path: &str) {
	let (server, addrs, db) = app_server().await;
	let _handle = tokio::spawn(server);

	// Add valid login links
	for i in 0..10 {
		let link = format!("valid-link-{i}");
		sqlx::query("INSERT INTO login_links (link, created_at) VALUES (?, datetime('now'))")
			.bind(&link)
			.execute(&db)
			.await
			.unwrap();
	}

	let mut cmd = std::process::Command::new("hurl");
	cmd.arg("--base-url")
		.arg(format!("http://127.0.0.1:{}", addrs[0].port()))
		.arg(hurl_path);

	let output = cmd.output().expect("failed to execute hurl command");

	if !output.status.success() {
		eprintln!("hurl stdout:\n{}", String::from_utf8_lossy(&output.stdout));
		eprintln!("hurl stderr:\n{}", String::from_utf8_lossy(&output.stderr));
		panic!("hurl test failed for {hurl_path}");
	}
}
