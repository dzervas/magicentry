//! This module holds the structs for managing the config file - `config.yaml`
//! by default
//!
//! YAML was chosen because the main target group are devops-adjacent people,
//! but serde makes sure that we're not married to that choice.

use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::request::Parts;
use chrono::Duration;
use lettre::transport::smtp;
use notify::{PollWatcher, Watcher};
use serde::{Deserialize, Serialize, Serializer};
use tracing::{error, info};

use crate::CONFIG;
use crate::database::{ConfigKVRow, Database};
use crate::service::Services;
use crate::user::User;
use crate::user_store::{FileUserStore, SQLUserStore, StaticUserStore, UserStore};

macro_rules! config_struct {
	(
		$(
			$(#[$meta:meta])*
			$pub:vis $name:ident: $type:ty = $default:expr
		),+ $(,)?
	) => {

		/// The actual, deserialized config data
		///
		/// To see what each field represents check out the [config.sample.yaml](https://github.com/dzervas/magicentry/blob/main/config.sample.yaml) file
		///
		/// TODO: Move the comments from here to the config.sample.yaml so the code
		/// is the source of truth
		// TODO: Generate a validation schema
        #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct Config {
            $(
	            $(#[$meta])*
	            $pub $name: $type
            ),+
        }

        impl Default for Config {
            fn default() -> Self {
                Self {
                    $( $name: $default ),+
                }
            }
        }

        impl Config {
            pub async fn update_field(config_arc: Arc<ArcSwap<Config>>, db: &Database, field: &str, value: serde_json::Value) -> anyhow::Result<()> {
                let config_full = config_arc.load().to_owned();
                let mut config = Arc::unwrap_or_clone(config_full);
                match field {
                    $(
	                    stringify!($name) => {
	                        config.$name = serde_json::from_value::<$type>(value)?;
	                    },
                    )+
                    _ => anyhow::bail!("Unknown field: {field}"),
                };

                config.save_to_db(db).await?;
                config.replace(config_arc).await?;
                Ok(())
            }
        }
    };
}

config_struct! {
	pub database_url: String = std::env::var("DATABASE_URL").unwrap_or("sqlite://database.db".to_string()),

	pub listen_host: String = std::env::var("LISTEN_HOST").unwrap_or("127.0.0.1".to_string()),
	pub listen_port: u16 = std::env::var("LISTEN_PORT").unwrap_or("8080".to_string()).parse().unwrap(),
	pub path_prefix: String = "/".to_string(),
	pub external_url: String = "http://localhost:8080".to_string(),
	pub static_path: String = "static".to_string(),

	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::config::serialize_duration_chrono"
	)]
	pub link_duration: Duration = Duration::try_hours(12).unwrap(),
	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::config::serialize_duration_chrono"
	)]
	pub session_duration: Duration = Duration::try_days(30).unwrap(),
	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::config::serialize_duration_chrono"
	)]
	pub secrets_cleanup_interval: Duration = Duration::try_hours(24).unwrap(),

	pub title: String = "MagicEntry".to_string(),

	pub auth_url_enable: bool = true,
	pub auth_url_user_header: String = "X-Auth-User".to_string(),
	pub auth_url_name_header: String = "X-Auth-Name".to_string(),
	pub auth_url_email_header: String = "X-Auth-Email".to_string(),
	pub auth_url_realms_header: String = "X-Auth-Realms".to_string(),

	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::config::serialize_duration_chrono"
	)]
	pub oidc_code_duration: Duration = Duration::try_minutes(1).unwrap(),

	pub saml_cert_pem_path: String = "saml_cert.pem".to_string(),
	pub saml_key_pem_path: String = "saml_key.pem".to_string(),

	pub smtp_enable: bool = false,
	pub smtp_url: String = "smtp://localhost:25".to_string(),
	pub smtp_from: String = "{title} <magicentry@example.com>".to_string(),
	pub smtp_subject: String = "{title} Login".to_string(),
	pub smtp_body: String = "Click the link to login: {magic_link}".to_string(),

	pub request_enable: bool = false,
	pub request_url: String = "https://www.cinotify.cc/api/notify".to_string(),
	pub request_method: String = "POST".to_string(),
	pub request_data: Option<String> = Some(std::env::var("REQUEST_DATA").unwrap_or("to={email}&subject={title} Login&body=Click the link to login: <a href=\"{magic_link}\">Login</a>&type=text/html".to_string())),
	pub request_content_type: String = "application/x-www-form-urlencoded".to_string(),

	pub webauthn_enable: bool = true,

	users: Vec<User> = vec![],
	pub users_file: Option<String> = None,
	pub users_sql_query_all: Option<String> = None,
	pub users_sql_query_email: Option<String> = None,
	pub users_sql_url: Option<String> = None,
	pub services: Services = Services::default(),
}

impl Config {
	/// Read the config file from the specified path and return the loaded config
	pub async fn reload_from_path(path: &str) -> anyhow::Result<Self> {
		info!("Loading config from {}", path);

		let mut new_config = serde_yaml::from_str::<Self>(&std::fs::read_to_string(path)?)?;

		if let Some(users_file) = &new_config.users_file {
			new_config.users.extend(serde_yaml::from_str::<Vec<User>>(
				&std::fs::read_to_string(users_file)?,
			)?);
		}

		Ok(new_config)
	}

	/// Read the config file as dictated by the `CONFIG_FILE` variable
	/// and replace the current contents
	///
	/// Note that live-updating the `CONFIG_FILE` environment variable
	/// is **NOT** supported (and is probably impossible anyway)
	pub async fn reload(config_path: &str, config: Arc<ArcSwap<Config>>) -> anyhow::Result<()> {
		let new_config = Self::reload_from_path(config_path).await?;
		new_config.replace(config).await?;
		Ok(())
	}

	/// Set up a file watcher for the specified config file path
	pub fn watch(config_path: &str, config: Arc<ArcSwap<Config>>) -> PollWatcher {
		Self::watch_with_interval(config_path, config, std::time::Duration::from_secs(2))
	}

	/// Set up a file watcher for the specified config file path with custom interval
	pub fn watch_with_interval(
		config_path: &str,
		config: Arc<ArcSwap<Config>>,
		poll_interval: std::time::Duration,
	) -> PollWatcher {
		let config_clone = config.clone();
		let config_path_clone = config_path.to_owned();
		let watcher_config = notify::Config::default()
			.with_compare_contents(true)
			.with_poll_interval(poll_interval)
			.with_follow_symlinks(true);

		let mut watcher = notify::PollWatcher::new(
			move |res| match res {
				Ok(_) => {
					info!("Config file changed, reloading");
					futures::executor::block_on(async {
						if let Err(e) = Self::reload(&config_path_clone, config_clone.clone()).await
						{
							error!("Failed to reload config file: {e}");
						}
					});
				}
				Err(e) => error!("Watch error: {:?}", e),
			},
			watcher_config,
		)
		.expect("Failed to create watcher for the config file");

		watcher
			.watch(Path::new(config_path), notify::RecursiveMode::NonRecursive)
			.expect("Failed to watch config file for changes");

		// Watch users file if it exists in current config
		let config_ref = config.load();
		if let Some(users_file) = &config_ref.users_file {
			watcher
				.watch(Path::new(users_file), notify::RecursiveMode::NonRecursive)
				.expect("Failed to watch users file for changes");
		}

		watcher
	}

	/// Read the SAML certificate from the [`saml_cert_pem_path`](ConfigFile::saml_cert_pem_path)
	/// filepath
	#[allow(clippy::single_char_pattern)]
	pub fn get_saml_cert(&self) -> Result<String, std::io::Error> {
		let data = std::fs::read_to_string(&self.saml_cert_pem_path)?;
		Ok(data
			.lines()
			.filter(|line| !line.contains("BEGIN CERTIFICATE") && !line.contains("END CERTIFICATE"))
			.collect::<String>()
			.replace("\n", ""))
	}

	/// Read the SAML private key from the [`saml_key_pem_path`](ConfigFile::saml_key_pem_path)
	/// filepath
	#[allow(clippy::single_char_pattern)]
	pub fn get_saml_key(&self) -> Result<String, std::io::Error> {
		let data = std::fs::read_to_string(&self.saml_key_pem_path)?;
		Ok(data
			.lines()
			.filter(|line| !line.contains("BEGIN PRIVATE KEY") && !line.contains("END PRIVATE KEY"))
			.collect::<String>()
			.replace("\n", ""))
	}

	pub fn get_user_store(&self) -> anyhow::Result<Arc<dyn UserStore>> {
		if self.users.len() > 0 {
			// TODO: This does not hot-reload
			return Ok(Arc::new(StaticUserStore::new(self.users.clone())));
		}

		if let Some(users_file) = self.users_file.clone() {
			return Ok(Arc::new(FileUserStore::new(users_file)));
		}

		if let Some(url) = self.users_sql_url.clone() {
			let Some(query_all) = self.users_sql_query_all.clone() else {
				return Err(anyhow::anyhow!(
					"users_sql_query_all is required when users_sql_url is set"
				));
			};
			let Some(query_email) = self.users_sql_query_email.clone() else {
				return Err(anyhow::anyhow!(
					"users_sql_query_email is required when users_sql_url is set"
				));
			};

			return Ok(Arc::new(SQLUserStore::new(&url, query_all, query_email)?));
		}

		error!("No users configured, using an empty user store");
		// TODO: This does not hot-reload
		Ok(Arc::new(StaticUserStore::new(vec![])))
	}

	pub fn get_link_senders(&self) -> Vec<Arc<dyn crate::LinkSender>> {
		let mut result: Vec<Arc<dyn crate::LinkSender>> = vec![];
		if self.smtp_enable {
			let smtp_url = std::env::var("SMTP_URL").unwrap_or(self.smtp_url.clone());
			let smtp_inst = smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&smtp_url)
				.expect("Failed to create mailer - is the `smtp_url` correct?")
				.pool_config(smtp::PoolConfig::new())
				.build();
			result.push(Arc::new(smtp_inst));
		}
		if self.request_enable {
			result.push(Arc::new(reqwest::Client::new()));
		}

		result
	}

	async fn replace(self, config: Arc<ArcSwap<Config>>) -> anyhow::Result<()> {
		let new_config_arc = Arc::new(self);

		// TODO: secrets and static pages still use the global config, updating it for the time being
		let mut config_guard = CONFIG.write().await;
		*config_guard = new_config_arc.clone();
		config.store(new_config_arc);
		Ok(())
	}

	/// Enterprise-only feature
	pub async fn load_from_db(db: &Database) -> anyhow::Result<Option<Self>> {
		info!("Loading config from database");
		let config = ConfigKV::get(&ConfigKeys::Config, db)
			.await?
			.and_then(|c| serde_json::from_str::<Self>(&c).ok());
		Ok(config)
	}

	pub async fn reload_from_db(config: Arc<ArcSwap<Config>>, db: &Database) -> anyhow::Result<()> {
		let Some(new_config) = Self::load_from_db(db).await? else {
			return Err(anyhow::anyhow!("Failed to load config from database"));
		};
		new_config.replace(config).await?;
		Ok(())
	}

	pub async fn save_to_db(&self, db: &Database) -> anyhow::Result<()> {
		info!("Saving config to database");
		ConfigKV::set(&ConfigKeys::Config, Some(serde_json::to_string(self)?), db).await?;
		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(transparent)]
pub struct LiveConfig(pub Arc<Config>);

impl<S: Send + Sync> FromRequestParts<S> for LiveConfig {
	type Rejection = StatusCode;

	async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
		parts
			.extensions
			.get::<Arc<Config>>()
			.cloned()
			.map(Self)
			.ok_or(StatusCode::INTERNAL_SERVER_ERROR)
	}
}

impl From<Arc<Config>> for LiveConfig {
	fn from(config: Arc<Config>) -> Self {
		Self(config)
	}
}

impl Deref for LiveConfig {
	type Target = Config;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

/// Basic key-value store database schema for some minor config values,
/// JWT private key for example
///
/// Uses the [`ConfigKeys`] enum for the keys as there should ever be only one
/// of each type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigKV {
	pub key: ConfigKeys,
	pub value: Option<String>,
}

impl ConfigKV {
	/// Set the provided key to the provided value - overwrites any previous values
	pub async fn set(key: &ConfigKeys, value: Option<String>, db: &Database) -> anyhow::Result<()> {
		let key_str = serde_json::to_string(&key)?;
		let value_str = value.unwrap_or_default();

		let row = ConfigKVRow {
			key: key_str,
			value: value_str,
			updated_at: None,
		};

		Ok(row.save(db).await?)
	}

	/// Get a config value by key
	pub async fn get(key: &ConfigKeys, db: &Database) -> anyhow::Result<Option<String>> {
		let key_str = serde_json::to_string(key)?;
		Ok(ConfigKVRow::get(&key_str, db).await?)
	}
}

/// The available keys for the [`ConfigKV`]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConfigKeys {
	Secret,
	JWTSecret,
	JWTPrivateKey,
	Config,
}

fn serialize_duration_chrono<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
	S: Serializer,
{
	let duration_str = format!(
		"{}s + {}ns",
		duration.num_seconds(),
		duration.subsec_nanos()
	);
	serializer.serialize_str(&duration_str)
}
