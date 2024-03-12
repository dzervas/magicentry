use chrono::Duration;
use serde::Deserialize;
use sqlx::{query, Error, SqlitePool};

use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(default)]
pub struct ConfigFile {
	pub database_url: String,

	pub listen_host: String,
	pub listen_port: u16,
	pub path_prefix: String,
	pub hostname: String,

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
	pub auth_url_realm_header: String,

	pub oidc_enable: bool,
	#[serde(deserialize_with = "duration_str::deserialize_duration_chrono")]
	pub oidc_code_duration: Duration,
	pub oidc_clients: Vec<crate::oidc::model::OIDCClient>,

	pub smtp_enable: bool,
	pub smtp_url: String,
	pub smtp_from: String,
	pub smtp_subject: String,
	pub smtp_body: String,

	pub request_enable: bool,
	pub request_url: String,
	pub request_method: String,
	pub request_data: Option<String>,

	pub users: Vec<User>,
}

impl Default for ConfigFile {
	fn default() -> Self {
		Self {
			database_url: "sqlite://database.sqlite3".to_string(),

			listen_host: "127.0.0.1".to_string(),
			listen_port: 8080,
			path_prefix: "/".to_string(),
			hostname   : "localhost".to_string(),

			link_duration   : Duration::try_hours(12).unwrap(),
			session_duration: Duration::try_days(30).unwrap(),

			title: "Just Passwordless".to_string(),
			static_path: "static".to_string(),

			auth_url_enable      : true,
			auth_url_user_header : "Remote-User".to_string(),
			auth_url_email_header: "Remote-Email".to_string(),
			auth_url_name_header : "Remote-Name".to_string(),
			auth_url_realm_header: "Remote-Group".to_string(),

			oidc_enable       : true,
			oidc_code_duration: Duration::try_minutes(1).unwrap(),
			oidc_clients      : vec![],

			smtp_enable : false,
			smtp_url    : "smtp://localhost:25".to_string(),
			smtp_from   : "Just Passwordless <just-passwordless@example.com>".to_string(),
			smtp_subject: "Just Passwordless Login".to_string(),
			smtp_body   : "Click the link to login: {link}".to_string(),

			request_enable: false,
			request_url   : "https://www.cinotify.cc/api/notify".to_string(),
			request_method: "POST".to_string(),
			request_data  : Some("to={email}&subject=Just Passwordless Login&body=http://localhost:8080/login/{magic}".to_string()),

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

		format!("{}://{}{}", scheme, host, self.path_prefix)
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConfigKV {
	pub key: String,
	pub value: Option<String>,
}

impl ConfigKV {
	pub async fn get(db: &SqlitePool, name: &str) -> Option<String> {
		let record = query!("SELECT * FROM config WHERE key = ?", name)
			.fetch_one(db)
			.await;

		if let Ok(record) = record {
			record.value.clone()
		} else {
			None
		}
	}

	pub async fn set(db: &SqlitePool, name: &str, new_value: &str) -> Result<(), Error> {
		query!(
				"INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
				name,
				new_value,
				new_value
			)
			.execute(db)
			.await?;
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::*;

	// #[actix_web::test]
	// async fn test_config_file() {
	// 	let toml_str = r#"
	// 		[users]
	// 		"valid@example.com" = ["realm1", "realm2"]
	// 		"#;
	// }

	#[actix_web::test]
	async fn test_config_kv() {
		let db = &db_connect().await;

		// Test set method
		ConfigKV::set(&db, "test_key", "test_value").await.unwrap();
		let value = ConfigKV::get(&db, "test_key").await.unwrap();
		assert_eq!(value, "test_value");

		ConfigKV::set(&db, "test_key", "new_value").await.unwrap();
		let value = ConfigKV::get(&db, "test_key").await.unwrap();
		assert_eq!(value, "new_value");

		// Test get method with non-existent key
		let value = ConfigKV::get(&db, "non_existent").await;
		assert!(value.is_none());
	}
}
