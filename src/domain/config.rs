use chrono::Duration;
use serde::Serializer;

use crate::service::Services;
use crate::user::User;

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
		#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
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
			pub async fn update_field(&mut self, field: &str, value: serde_json::Value) -> anyhow::Result<()> {
				match field {
					$(
						stringify!($name) => {
							self.$name = serde_json::from_value::<$type>(value)?;
						},
					)+
					_ => anyhow::bail!("Unknown field: {field}"),
				};
				Ok(())
			}
		}
	};
}

config_struct! {
	pub path_prefix: String = "/".to_string(),
	pub external_url: String = "http://localhost:8080".to_string(),

	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::domain::config::serialize_duration_chrono"
	)]
	pub link_duration: Duration = Duration::try_hours(12).unwrap(),
	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::domain::config::serialize_duration_chrono"
	)]
	pub session_duration: Duration = Duration::try_days(30).unwrap(),
	#[serde(
		deserialize_with = "duration_str::deserialize_duration_chrono",
		serialize_with = "crate::domain::config::serialize_duration_chrono"
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
		serialize_with = "crate::domain::config::serialize_duration_chrono"
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

/// Serialize a duration as a string in the format "seconds + nanoseconds" so that duration_str
/// can deserialize it back.
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
