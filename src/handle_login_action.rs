use std::collections::BTreeMap;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::{post, web, HttpRequest, HttpResponse};
use formatx::formatx;
use lettre::message::header::ContentType as LettreContentType;
use lettre::{AsyncTransport, Message};
use log::{debug, info};
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::token::MagicLinkToken;
use crate::user::User;
use crate::utils::get_partial;
use crate::{SmtpTransport, CONFIG, SCOPED_LOGIN};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LoginInfo {
	pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopedLogin {
	#[serde(rename = "rd")]
	pub(crate) scope_app_url: String,
}

impl ScopedLogin {
	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = urlencoding::decode(&self.scope_app_url).ok()?.to_string();
		let redirect_url_clean = redirect_url.split("?").next()?.trim_end_matches('/');
		let redirect_uri = redirect_url_clean.parse::<Uri>().ok()?;

		let origin_authority = redirect_uri.authority()?;
		let origin_scheme = redirect_uri.scheme()?;
		let origin = format!("{}://{}", origin_scheme, origin_authority);

		let config = CONFIG.read().await;
		let config_scope = config
			.auth_url_scopes
			.iter()
			.find(|c| user.has_any_realm(&c.realms) && c.origin == origin);

		if config_scope.is_none() {
			log::warn!("Invalid redirect_uri: {}", redirect_url);
			return None;
		}

		Some(format!("{}/magicentry/auth-url/login-code?code={}", origin, code))
	}
}

impl From<String> for ScopedLogin {
	fn from(scope: String) -> Self {
		ScopedLogin { scope_app_url: scope }
	}
}

impl From<ScopedLogin> for String {
	fn from(scoped: ScopedLogin) -> Self {
		scoped.scope_app_url
	}
}

#[post("/login")]
async fn login_action(
	req: HttpRequest,
	session: Session,
	form: web::Form<LoginInfo>,
	db: web::Data<reindeer::Db>,
	mailer: web::Data<Option<SmtpTransport>>,
	http_client: web::Data<Option<reqwest::Client>>,
) -> Response {
	let login_action_page = get_partial("login_action", BTreeMap::new())?;
	let result = Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_action_page));
	let Some(user) = User::from_config(&form.email).await else {
		// Return 200 to avoid leaking valid emails
		return result;
	};

	// Generate the magic link
	let link = MagicLinkToken::new(&db, user.clone(), None, None).await?;
	let config = CONFIG.read().await;
	let base_url = config.url_from_request(&req);
	let magic_link = format!("{}/login/{}", base_url, link.code);
	let name = &user.name.clone();
	let username = &user.username.clone();

	debug!("Link: {} {:?}", &magic_link, link);

	// Send it via email
	if let Some(mailer) = mailer.as_ref() {
		let email = Message::builder()
			.from(config.smtp_from.parse()?)
			.to(user.email.parse()?)
			.subject(formatx!(&config.smtp_subject, title = &config.title)?)
			.header(LettreContentType::TEXT_HTML)
			.body(formatx!(
				&config.smtp_body,
				title = &config.title,
				magic_link = &magic_link,
				name = name,
				username = username
			)?)?;

		info!("Sending email to {}", &user.email);
		mailer.send(email).await?;
	}

	// And/or via HTTP
	if let Some(client) = http_client.as_ref() {
		let method = reqwest::Method::from_bytes(config.request_method.as_bytes())
			.expect("Invalid request_method provided in the config");
		let url = formatx!(
			&config.request_url,
			title = &config.title,
			magic_link = &magic_link,
			email = &user.email,
			name = name,
			username = username
		)?;
		let mut req = client.request(method, url);

		if let Some(data) = &config.request_data {
			let body = formatx!(
				data.as_str(),
				title = &config.title,
				magic_link = &magic_link,
				email = &user.email,
				name = name,
				username = username
			)?;
			req = req
				// TODO: Make this configurable
				.header(CONTENT_TYPE, config.request_content_type.as_str())
				.body(body);
		}

		info!("Sending request for user {}", &user.email);
		let resp = req.send().await?;
		if !resp.status().is_success() {
			log::warn!(
				"Request for user {} failed: {} {}",
				&user.email,
				resp.status(),
				resp.text().await.unwrap_or_default()
			);
		}
	}

	// If this is a scoped login, save the scope in the server session storage
	if let Ok(scoped) = serde_qs::from_str::<ScopedLogin>(req.query_string()) {
		debug!("Setting scoped login for link: {:?}", &scoped);
		session.insert(SCOPED_LOGIN, scoped)?;
	}

	result
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};
	use reindeer::Entity;

	#[actix_web::test]
	async fn test_login_action() {
		let db = &db_connect().await;
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.app_data(web::Data::new(None::<SmtpTransport>))
				.app_data(web::Data::new(None::<reqwest::Client>))
				.service(login_action),
		)
		.await;

		// Login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo {
				email: "valid@example.com".to_string(),
			})
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);

		// Invalid login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo {
				email: "invalid@example.com".to_string(),
			})
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);

		let links =
			MagicLinkToken::get_with_filter(|t| t.user == "invalid@example.com", db).unwrap();
		assert!(links.is_empty());
	}
}
