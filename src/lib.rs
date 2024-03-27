use config::ConfigFile;
use lazy_static::lazy_static;

pub mod auth_url;
pub mod config;
pub mod error;
pub mod token;
pub mod oidc;
pub mod user;
pub mod utils;
pub mod webauthn;

pub mod handle_index;
pub mod handle_login_page;
pub mod handle_login_action;
pub mod handle_login_link;
pub mod handle_logout;
pub mod handle_static;

#[cfg(test)]
pub mod tests;

pub const AUTHORIZATION_COOKIE: &str = "oidc_authorization";
pub const PROXIED_COOKIE: &str = "code";
pub const RANDOM_STRING_LEN: usize = 32;
pub const SCOPED_LOGIN: &str = "scope";
pub const SCOPED_SESSION_COOKIE: &str = "scoped_session_id";
pub const SESSION_COOKIE: &str = "session_id";

#[cfg(not(test))]
pub type SmtpTransport = lettre::transport::smtp::AsyncSmtpTransport<lettre::Tokio1Executor>;
#[cfg(not(test))]
lazy_static! {
	static ref CONFIG_FILE: String = std::env::var("CONFIG_FILE").unwrap_or("config.yaml".to_string());
}

#[cfg(test)]
pub type SmtpTransport = lettre::transport::stub::AsyncStubTransport;
#[cfg(test)]
lazy_static! {
	pub static ref CONFIG_FILE: String = "config.sample.yaml".to_string();
}

lazy_static! {
	pub static ref CONFIG: ConfigFile = serde_yaml::from_str::<ConfigFile>(
		&std::fs::read_to_string(CONFIG_FILE.as_str())
			.expect(format!("Unable to open config file `{:?}`", CONFIG_FILE.as_str()).as_str())
		)
		.expect(format!("Unable to parse config file `{:?}`", CONFIG_FILE.as_str()).as_str());
}
