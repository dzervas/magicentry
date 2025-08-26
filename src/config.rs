//! This module holds the structs for managing the config file - `config.yaml`
//! by default
//!
//! YAML was chosen because the main target group are devops-adjacent people,
//! but serde makes sure that we're not married to that choice.

use std::path::Path;

use chrono::Duration;
use log::error;
use notify::{PollWatcher, Watcher};
use serde::{Deserialize, Serialize};

use crate::database::{ConfigKVRow, Database};
use crate::service::Services;
use crate::user::User;
use crate::{CONFIG, CONFIG_FILE};

/// The actual, deserialized config data
///
/// To see what each field represents check out the [config.sample.yaml](https://github.com/dzervas/magicentry/blob/main/config.sample.yaml) file
///
/// TODO: Move the comments from here to the config.sample.yaml so the code
/// is the source of truth
// TODO: Generate a validation schema
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigFile {
	pub database_url: String,

	pub listen_host: String,
	pub listen_port: u16,
	pub path_prefix: String,
	pub external_url: String,

	#[serde(deserialize_with = "duration_str::deserialize_duration_chrono")]
	pub link_duration: Duration,
	#[serde(deserialize_with = "duration_str::deserialize_duration_chrono")]
	pub session_duration: Duration,

	pub title: String,
	pub static_path: String,

	pub auth_url_enable: bool,
	pub auth_url_user_header: String,
	pub auth_url_name_header: String,
	pub auth_url_email_header: String,
	pub auth_url_realms_header: String,

	#[serde(deserialize_with = "duration_str::deserialize_duration_chrono")]
	pub oidc_code_duration: Duration,

	pub saml_cert_pem_path: String,
	pub saml_key_pem_path: String,

	pub smtp_enable: bool,
	pub smtp_url: String,
	pub smtp_from: String,
	pub smtp_subject: String,
	pub smtp_body: String,

	pub request_enable: bool,
	pub request_url: String,
	pub request_method: String,
	pub request_data: Option<String>,
	pub request_content_type: String,

	pub webauthn_enable: bool,

	// pub force_https_redirects: bool,
	/// Path to a file containing the user definitions
	pub users_file: Option<String>,
	pub users: Vec<User>,
	pub services: Services,
}

impl Default for ConfigFile {
	fn default() -> Self {
		Self {
			database_url: std::env::var("DATABASE_URL").unwrap_or("database.db".to_string()),

			listen_host : std::env::var("LISTEN_HOST").unwrap_or("127.0.0.1".to_string()),
			listen_port : std::env::var("LISTEN_PORT").unwrap_or("8080".to_string()).parse().unwrap(),
			path_prefix : "/".to_string(),
			external_url: "http://localhost:8080".to_string(),

			link_duration   : Duration::try_hours(12).unwrap(),
			session_duration: Duration::try_days(30).unwrap(),

			title: "MagicEntry".to_string(),
			static_path: "static".to_string(),

			auth_url_enable       : true,
			auth_url_user_header  : "X-Remote-User".to_string(),
			auth_url_email_header : "X-Remote-Email".to_string(),
			auth_url_name_header  : "X-Remote-Name".to_string(),
			auth_url_realms_header: "X-Remote-Realms".to_string(),

			oidc_code_duration: Duration::try_minutes(1).unwrap(),

			saml_cert_pem_path: "saml_cert.pem".to_string(),
			saml_key_pem_path : "saml_key.pem".to_string(),

			smtp_enable : false,
			smtp_url    : "smtp://localhost:25".to_string(),
			smtp_from   : "{title} <magicentry@example.com>".to_string(),
			smtp_subject: "{title} Login".to_string(),
			smtp_body   : "Click the link to login: {magic_link}".to_string(),

			request_enable      : false,
			request_url         : "https://www.cinotify.cc/api/notify".to_string(),
			request_method      : "POST".to_string(),
			request_data        : Some("to={email}&subject={title} Login&body=Click the link to login: <a href=\"{magic_link}\">Login</a>&type=text/html".to_string()),
			request_content_type: "application/x-www-form-urlencoded".to_string(),

			webauthn_enable: true,

			// force_https_redirects: true,

			users_file: None,
			users: vec![],

			services: Services(vec![]),
        }
    }
}

impl ConfigFile {
	/// This function returns the base URL that magicentry was accessed from
	///
	/// Useful to return correct links for proxied requests that do not abide
	/// by the [external_url](ConfigFile::external_url) host
	pub fn url_from_request(&self, request: &actix_web::HttpRequest) -> String {
		let conn = request.connection_info();
		let host = conn.host();
		let scheme = if conn.scheme() == "http" {
			"http"
		} else {
			"https"
		};

		let path_prefix = if self.path_prefix.ends_with('/') {
			&self.path_prefix[..self.path_prefix.len() - 1]
		} else {
			&self.path_prefix
		};

		format!("{}://{}{}", scheme, host, path_prefix)
	}

	/// Read the config file as dictated by the CONFIG_FILE variable
	/// and replace the current contents
	///
	/// Note that live-updating the CONFIG_FILE environment variable
	/// is **NOT** supported
	pub async fn reload() -> crate::error::Result<()> {
		let mut config = CONFIG.write().await;
		log::info!("Reloading config from {}", CONFIG_FILE.as_str());

		let mut new_config = serde_yaml::from_str::<ConfigFile>(
			&std::fs::read_to_string(CONFIG_FILE.as_str())?
		)?;

		if let Some(users_file) = &new_config.users_file {
			new_config.users.extend(
				serde_yaml::from_str::<Vec<User>>(
					&std::fs::read_to_string(users_file)?
				)?
			);
		}

		if new_config.users_file != config.users_file {
			error!("Users file path changed, live watching new paths is not supported, please restart the server");
		}

		*config = new_config;
		Ok(())
	}

	/// Set up a file watcher that fires the [reload](ConfigFile::reload) method so
	/// that config file changes get automatically picked up
	pub fn watch() -> PollWatcher {
		let watcher_config = notify::Config::default()
			.with_compare_contents(true)
			.with_poll_interval(std::time::Duration::from_secs(2))
			.with_follow_symlinks(true);

		let mut watcher = notify::PollWatcher::new(move |_| {
			log::info!("Config file changed, reloading");
			futures::executor::block_on(async {
				if let Err(e) = ConfigFile::reload().await {
					log::error!("Failed to reload config file: {}", e);
				}
			})
		}, watcher_config)
			.expect("Failed to create watcher for the config file");

		watcher
			.watch(Path::new(CONFIG_FILE.as_str()), notify::RecursiveMode::NonRecursive)
			.expect("Failed to watch config file for changes");

		if let Some(users_file) = CONFIG
			.try_read()
			.ok()
			.and_then(|c| c.users_file.clone())
		{
			watcher
				.watch(Path::new(&users_file), notify::RecursiveMode::NonRecursive)
				.expect("Failed to watch users file for changes");
		}

		watcher
	}

	/// Read the SAML certificate from the [saml_cert_pem_path](ConfigFile::saml_cert_pem_path)
	/// filepath
	pub fn get_saml_cert(&self) -> Result<String, std::io::Error> {
		let data = std::fs::read_to_string(&self.saml_cert_pem_path)?;
		Ok(data
			.lines()
			.filter(|line| !line.contains("BEGIN CERTIFICATE") && !line.contains("END CERTIFICATE"))
			.collect::<String>()
			.replace("\n", ""))
	}

	/// Read the SAML private key from the [saml_key_pem_path](ConfigFile::saml_key_pem_path)
	/// filepath
	pub fn get_saml_key(&self) -> Result<String, std::io::Error> {
		let data = std::fs::read_to_string(&self.saml_key_pem_path)?;
		Ok(data
			.lines()
			.filter(|line| {
				!line.contains("BEGIN PRIVATE KEY") && !line.contains("END PRIVATE KEY")
			})
			.collect::<String>()
			.replace("\n", ""))
	}
}

/// Basic key-value store database schema for some minor config values,
/// JWT private key for example
///
/// Uses the [ConfigKeys] enum for the keys as there should ever be only one
/// of each type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigKV {
	pub key: ConfigKeys,
	pub value: Option<String>,
}

impl ConfigKV {
	/// Set the provided key to the provided value - overwrites any previous values
	pub async fn set(key: ConfigKeys, value: Option<String>, db: &Database) -> crate::error::Result<()> {
		let key_str = serde_json::to_string(&key)?;
		let value_str = value.unwrap_or_default();
		
		let row = ConfigKVRow {
			key: key_str,
			value: value_str,
			updated_at: None,
		};
		
		row.save(db).await
	}
	
	/// Get a config value by key
	pub async fn get(key: &ConfigKeys, db: &Database) -> crate::error::Result<Option<String>> {
		let key_str = serde_json::to_string(key)?;
		ConfigKVRow::get(&key_str, db).await
	}
}

/// The available keys for the [ConfigKV]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfigKeys {
	Secret,
	JWTKeyPair,
}

// Remove AsBytes trait as it's no longer needed for SQLx
