#![forbid(unsafe_code)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

//! # `MagicEntry`
//!
//! A smol identity provider.
//!
//! This documentation is targeted to contributors and auditors.
//! `MagicEntry` is not a library and that's why the code and docs do not live
//! in crates.io and docs.io. My thought was to have this page open alongside
//! the code to be able to traverse and understand code & protocols faster.
//!
//! The code is split as I saw fit, in the following structure:
//! - `src/*.rs`: Code that implements the "core" functionality of the app - config, login, logout, static files, etc.
//! - `secret/`: This came more of a necessity as it's very much a core functionality but I wanted to have a directory to glance over the very-security-related code
//! - `auth_url`: Oof this was a curve ball. It's essentially an authentication/authorization protocol, much like SAML or OIDC but nginx and other reverse proxies implement it at will, without a spec. Check out the module for more info
//! - `oidc`: `OpenID` Connect implementation
//! - `saml`: SAML implementation - a hacky one but it works
//! - `webauthn`: Passkey login implementation - allows a user to register and authenticate with a passkey
//!
//! ## Tests
//!
//! While the project is not test-driven, some aspects of the application has
//! proven to be fragile in some aspects (most notably post-login redirects,
//! webauthn login and group matching) and a need for proper end-to-end tests
//! has arose.
//!
//! While I tried to use rust's excellent test harness, the resulting code
//! is too cumbersome and breaks too often, due to internal changes,
//! that's why the "main" e2e tests are in [hurl](https://hurl.dev). It's
//! a way to define HTTP requests and assert the responses in an easy to understand,
//! almost plain-text manner.
//!
//! The easiest way to run them is as follows:
//!
//! ```bash
//! pnpm test
//! ```
//!
//! The script sets up a magicentry server with the `config.sample.yaml` as
//! a config file, a tiny webserver serving the `./hurl` directory (we'll get there)
//! and finally fires up hurl to execute the actual test requests.
//!
//! It should automatically watch for file changes and re-do all the tests,
//! a nice way to fix some bugs

use std::sync::{Arc, LazyLock};

use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::{config::Config, user::User};

pub mod app_build;
pub mod auth_url;
pub mod config;
#[cfg(feature = "kube")]
pub mod config_kube;
pub mod database;
pub mod error;
pub mod oidc;
pub mod saml;
pub mod service;
pub mod user;
pub mod secret;
pub mod utils;
pub mod webauthn;

pub mod handle_index;
pub mod handle_login_post;
pub mod handle_magic_link;
pub mod handle_login;
pub mod handle_logout;
pub mod handle_static;

pub mod pages;

#[cfg(test)]
pub mod tests;

/// The name of the cookie used to store the authorization code during OIDC -
/// for more check [oidc]
pub const AUTHORIZATION_COOKIE: &str = "oidc_authorization";

/// The query parameter name used to authenticate a session across a proxy -
/// for more check [`auth_url`]
pub const PROXY_QUERY_CODE: &str = "magicentry_code";
/// The header that the proxy sends to the auth-url endpoint that includes
/// the original URL - used to get the [`PROXY_QUERY_CODE`]
pub const PROXY_ORIGIN_HEADER: &str = "X-Original-URL"; // Works for ingress-nginx, what about the rest?
/// The name of the cookie used to store a long-lived session under a different domain (proxied) - for [`auth_url`] usage
pub const PROXY_SESSION_COOKIE: &str = "magicentry_session_id";
/// String size of the generated secrets -
/// recommended to be at least 32 but under 128 (entropy is not free)
pub const RANDOM_STRING_LEN: usize = 32;
/// The name of the cookie to store a normal, global browser session
pub const SESSION_COOKIE: &str = "session_id";

/// The type of the database, use it instead of the concrete type
/// to aid a bit on the transition to come to a new db
pub type Database = sqlx::SqlitePool;

pub const JWT_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

/// The type of the [lettre](lettre::transport) `SmtpTransport`, defined to allow
/// for switching between actual and stub implementations during testing
#[cfg(not(test))]
pub type SmtpTransport = lettre::transport::smtp::AsyncSmtpTransport<lettre::Tokio1Executor>;

/// Config file path, taken from env vars during startup
/// or defaulting to `config.yaml` if not set
// Needs lazy_static because we want to read the env var on runtime
#[cfg(not(test))]
static CONFIG_FILE: LazyLock<String> = LazyLock::new(|| std::env::var("CONFIG_FILE").unwrap_or_else(|_| "config.yaml".to_string()));

#[cfg(test)]
pub type SmtpTransport = lettre::transport::stub::AsyncStubTransport;
#[cfg(test)]
pub static CONFIG_FILE: LazyLock<String> = LazyLock::new(|| "config.sample.yaml".to_string());

/// Global static that holds a read/write mutex to the [`Config`] struct
/// to allow for concurrent access to the config. I'm not proud but here we are
// Can this be kept in an actix app state? If so, how could the kube side
// access it - and even worse, write to it?
pub static CONFIG: LazyLock<RwLock<Arc<Config>>> = LazyLock::new(RwLock::default);

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct InFlightConfig(Arc<Config>);

#[derive(Clone)]
pub struct AppState {
	pub db: crate::Database,
	pub config: Arc<Config>,
	// pub mailer: Option<SmtpTransport>,
	// pub http_client: Option<reqwest::Client>,
	pub link_senders: Vec<Arc<dyn LinkSender>>,
}

impl AppState {
	pub async fn send_magic_link(&self, user: &User, link: &str) -> anyhow::Result<()> {
		// TODO: Make this concurrent and return multiple errors
		for sender in &self.link_senders {
			sender.send_magic_link(user, link, &self.config).await?;
		}

		Ok(())
	}
}

#[async_trait::async_trait]
pub trait LinkSender: Send + Sync {
	async fn send_magic_link(&self, user: &User, link: &str, config: &Config) -> anyhow::Result<()>;
}

#[async_trait::async_trait]
impl LinkSender for crate::SmtpTransport {
	async fn send_magic_link(&self, user: &User, link: &str, config: &Config) -> anyhow::Result<()> {
		use anyhow::Context as _;
		use lettre::{AsyncTransport, Message};
		use lettre::message::header::ContentType as LettreContentType;
		use formatx::formatx;

		let email = Message::builder()
			.from(config.smtp_from.parse()
				.context("Failed to parse SMTP 'from' address")?)
			.to(user.email.parse()
				.context("Failed to parse user email address")?)
			.subject(formatx!(&config.smtp_subject, title = &config.title)
				.context("Failed to format SMTP subject template")?)
			.header(LettreContentType::TEXT_HTML)
			.body(
				formatx!(
					&config.smtp_body,
					title = &config.title,
					magic_link = &link,
					name = user.name.clone(),
					username = user.username.clone()
				).context("Failed to format SMTP body template")?
			).context("Failed to build email message")?;

		self.send(email).await
			.context("Failed to send email via SMTP")?;

		Ok(())
	}
}

#[async_trait::async_trait]
impl LinkSender for reqwest::Client {
	async fn send_magic_link(&self, user: &User, link: &str, config: &Config) -> anyhow::Result<()> {
		use anyhow::Context as _;
		use reqwest::header::CONTENT_TYPE;
		use formatx::formatx;

		let method = reqwest::Method::from_bytes(config.request_method.as_bytes())
			.expect("Invalid request_method provided in the config");
		let url = formatx!(
			&config.request_url,
			title = &config.title,
			magic_link = &link,
			email = &user.email,
			name = user.name.clone(),
			username = user.username.clone()
		).context("Failed to format HTTP request URL template")?;
		let mut req = self.request(method, url);

		if let Some(data) = &config.request_data {
			let body = formatx!(
				data.as_str(),
				title = &config.title,
				magic_link = &link,
				email = &user.email,
				name = user.name.clone(),
				username = user.username.clone()
			).context("Failed to format HTTP request body template")?;
			req = req
				// TODO: Make this configurable
				.header(CONTENT_TYPE, config.request_content_type.as_str())
				.body(body);
		}

		info!("Sending request for user {}", &user.email);
		let resp = req.send().await
			.context("Failed to send HTTP request for magic link notification")?;

		if !resp.status().is_success() {
			warn!(
				"Request for user {} failed: {} {}",
				&user.email,
				resp.status(),
				resp.text().await.unwrap_or_default()
			);
		}

		Ok(())
	}
}
