use lazy_static::lazy_static;
use tokio::sync::RwLock;

use crate::config::ConfigFile;

pub mod auth_url;
pub mod config;
#[cfg(feature = "kube")]
pub mod config_kube;
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
	pub static ref CONFIG: RwLock<ConfigFile> = RwLock::new(ConfigFile::default());

	pub static ref TEMPLATES: handlebars::Handlebars<'static> = {
		let mut handlebars = handlebars::Handlebars::new();
		handlebars.register_templates_directory(
			"static/templates",
			handlebars::DirectorySourceOptions {
				tpl_extension: ".html.hbs".to_string(),
				..Default::default()
			}
		)
		.expect("Failed to register templates directory");

		// The partials are the same as the templates
		handlebars.register_templates_directory(
			"static/partials",
			handlebars::DirectorySourceOptions {
				tpl_extension: ".html.hbs".to_string(),
				..Default::default()
			}
		)
		.expect("Failed to register partials directory");

		#[cfg(debug_assertions)]
		handlebars.set_dev_mode(true);

		handlebars
	};
}
