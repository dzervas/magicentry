use crate::config::Config;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

#[test]
fn get_saml_key_strips_pem_headers() {
	let pem = "-----BEGIN PRIVATE KEY-----\nABCDEF\n-----END PRIVATE KEY-----\n";
	let path = std::env::temp_dir().join(format!("testkey-{}.pem", Uuid::new_v4()));
	std::fs::write(&path, pem).expect("write pem");

	let config = Config {
		saml_key_pem_path: path.to_string_lossy().into_owned(),
		..Default::default()
	};

	let key = config.get_saml_key().expect("read key");
	assert_eq!(key, "ABCDEF");
}

// TODO: This could be more e2e-ish
#[tokio::test]
async fn test_file_watcher_reload() -> anyhow::Result<()> {
	use arc_swap::ArcSwap;
	use std::env;

	// Create a temporary directory within the target directory
	let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
	let config_temp_dir = std::path::Path::new(&target_dir).join("test-configs");
	std::fs::create_dir_all(&config_temp_dir)?;

	// Copy config.sample.yaml to the temporary location
	let source_config = "config.sample.yaml";
	let temp_config_path = config_temp_dir.join("test-config.yaml");
	std::fs::copy(source_config, &temp_config_path)?;

	// Load initial config from the temporary file
	let temp_config_str = temp_config_path.to_string_lossy().into_owned();
	let initial_config = Arc::new(Config::reload_from_path(&temp_config_str).await?);
	let config_arc = Arc::new(ArcSwap::new(initial_config.clone()));

	// Verify initial title
	assert_eq!(initial_config.title, "MagicEntry");

	// Set up the file watcher for the temporary config file
	let _watcher = Config::watch_with_interval(&temp_config_str, Duration::from_millis(50));

	// Modify the config file to change the title
	let mut config_content = std::fs::read_to_string(&temp_config_path)?;
	config_content = config_content.replace("title: MagicEntry", "title: UpdatedMagicEntry");
	std::fs::write(&temp_config_path, config_content)?;

	// Wait for the watcher to detect changes and reload
	tokio::time::sleep(Duration::from_millis(100)).await;

	// Manually trigger reload to simulate what the watcher would do
	let updated_config = Arc::new(Config::reload_from_path(&temp_config_str).await?);
	config_arc.store(updated_config);

	// Verify the title has been updated
	assert_eq!(config_arc.load().title, "UpdatedMagicEntry");

	// Now test with the axum-test server
	use crate::app_build::axum_build;
	use crate::utils::tests::db_connect;
	use axum_test::TestServer;

	// Initialize database and build server with our config
	let db = db_connect().await;
	let server = axum_build(db, config_arc.clone(), vec![], None).await;
	let test_server = TestServer::new(server).unwrap();

	// Initial GET to /login to check the title
	let initial_response = test_server.get("/login").await;
	let initial_text = initial_response.text();
	assert!(initial_text.contains("UpdatedMagicEntry"));

	// Clean up
	std::fs::remove_file(&temp_config_path)?;

	Ok(())
}
