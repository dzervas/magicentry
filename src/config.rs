use chrono::Duration;
use notify::{RecommendedWatcher, Watcher};
use reindeer::{AsBytes, Db, Entity};
use serde::{Deserialize, Serialize};

use crate::user::User;
use crate::{CONFIG, CONFIG_FILE};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(default)]
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
	pub auth_url_scopes: Vec<crate::auth_url::AuthUrlScope>,

	pub oidc_enable: bool,
	#[serde(deserialize_with = "duration_str::deserialize_duration_chrono")]
	pub oidc_code_duration: Duration,
	pub oidc_clients: Vec<crate::oidc::client::OIDCClient>,

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

	pub users: Vec<User>,
}

impl Default for ConfigFile {
	fn default() -> Self {
		Self {
			database_url: std::env::var("DATABASE_URL").unwrap_or("database.db".to_string()),

			listen_host: std::env::var("LISTEN_HOST").unwrap_or("127.0.0.1".to_string()),
			listen_port: std::env::var("LISTEN_PORT").unwrap_or("8080".to_string()).parse().unwrap(),
			path_prefix: "/".to_string(),
			external_url: "http://localhost:8080".to_string(),

			link_duration   : Duration::try_hours(12).unwrap(),
			session_duration: Duration::try_days(30).unwrap(),

			title: "MagicEntry".to_string(),
			static_path: "static".to_string(),

			auth_url_enable      : true,
			auth_url_user_header : "X-Auth-User".to_string(),
			auth_url_email_header: "X-Auth-Email".to_string(),
			auth_url_name_header : "X-Auth-Name".to_string(),
			auth_url_realms_header: "X-Auth-Realms".to_string(),
			auth_url_scopes      : vec![],

			oidc_enable       : true,
			oidc_code_duration: Duration::try_minutes(1).unwrap(),
			oidc_clients      : vec![],

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

			users: vec![],
		}
	}
}

impl ConfigFile {
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

	pub async fn reload() -> crate::error::Result<()> {
		let mut config = CONFIG.write().await;
		log::info!("Reloading config from {}", CONFIG_FILE.as_str());
		*config = serde_yaml::from_str::<ConfigFile>(&std::fs::read_to_string(CONFIG_FILE.as_str())?)?;
		Ok(())
	}

	pub fn watch() -> RecommendedWatcher {
		let mut watcher = notify::recommended_watcher(
			move |_| {
				futures::executor::block_on(async {
					if let Err(e) = ConfigFile::reload().await {
						log::error!("Failed to reload config file: {}", e);
					}
				})
			},
		).expect("Failed to create watcher");

		watcher
			.watch(CONFIG_FILE.as_ref(), notify::RecursiveMode::NonRecursive)
			.expect("Failed to watch config file");

		watcher
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfigKeys {
	Secret,
	JWTKeyPair,
}

impl AsBytes for ConfigKeys {
	fn as_bytes(&self) -> Vec<u8> {
		vec![self.clone() as u8]
	}
}

#[derive(Entity, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[entity(name = "config", id = "key")]
pub struct ConfigKV {
	pub key: ConfigKeys,
	pub value: Option<String>,
}

impl ConfigKV {
	pub fn set(key: ConfigKeys, value: Option<String>, db: &Db) -> Result<(), reindeer::Error> {
		let config = Self {
			key,
			value,
		};

		config.save(db)
	}
}
