use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::{post, web, HttpRequest, HttpResponse};
use formatx::formatx;
use lettre::{AsyncTransport, Message};
use lettre::message::header::ContentType as LettreContentType;
use log::info;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::token::MagicLinkToken;
use crate::user::User;
use crate::{SmtpTransport, CONFIG, SCOPED_LOGIN};
use crate::utils::get_partial;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LoginInfo {
	pub email: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ScopedLogin {
	#[serde(rename = "rd")]
	pub(crate) scope: String,
}

impl ScopedLogin {
	pub fn get_redirect_url(&self, code: &str) -> Option<String> {
		let redirect_url = urlencoding::decode(&self.scope).ok()?.to_string();
		let redirect_url_clean = redirect_url.split("?").next()?.trim_end_matches('/');
		let redirect_uri = redirect_url_clean.parse::<Uri>().ok()?;

		// TODO: Check against the config for the valid scopes
		// let config_client = CONFIG.oidc_clients
		// 	.iter()
		// 	.find(|c|
		// 		c.id == self.client_id &&
		// 		c.redirect_uris.contains(&redirect_url));

		// if config_scope.is_none() {
		// 	log::warn!("Invalid redirect_uri: {} for client_id: {}", redirect_url, self.client_id);
		// 	return None;
		// }

		Some(format!("{}://{}/__magicentry_auth_code?code={}", redirect_uri.scheme()?, redirect_uri.authority()?, code))
	}
}

impl From<String> for ScopedLogin {
	fn from(scope: String) -> Self {
		ScopedLogin { scope }
	}
}

impl From<ScopedLogin> for String {
	fn from(scoped: ScopedLogin) -> Self {
		scoped.scope
	}
}

#[post("/login")]
async fn login_action(req: HttpRequest, session: Session, form: web::Form<LoginInfo>, db: web::Data<reindeer::Db>, mailer: web::Data<Option<SmtpTransport>>, http_client: web::Data<Option<reqwest::Client>>) -> Response {
	let login_action_page = get_partial("login_action");
	let result = Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_action_page));
	let Some(user) = User::from_config(&form.email) else {
		// Return 200 to avoid leaking valid emails
		return result;
	};

	let link = MagicLinkToken::new(&db, &user, None, None).await?;
	let base_url = CONFIG.url_from_request(&req);
	let magic_link = format!("{}/login/{}", base_url, link.code);
	let name = &user.name.clone().unwrap_or_default();
	let username = &user.username.clone().unwrap_or_default();

	#[cfg(debug_assertions)]
	println!("Link: {} {:?}", &magic_link, link);

	if let Some(mailer) = mailer.as_ref() {
		let email = Message::builder()
			.from(CONFIG.smtp_from.parse()?)
			.to(user.email.parse()?)
			.subject(formatx!(&CONFIG.smtp_subject, title = &CONFIG.title)?)
			.header(LettreContentType::TEXT_HTML)
			.body(formatx!(
				&CONFIG.smtp_body,
				title = &CONFIG.title,
				magic_link = &magic_link,
				name = name,
				username = username
			)?)?;

		info!("Sending email to {}", &user.email);
		mailer.send(email).await?;
	}

	if let Some(client) = http_client.as_ref() {
		let method = reqwest::Method::from_bytes(CONFIG.request_method.as_bytes()).expect("Invalid request_method provided in the config");
		let url = formatx!(
			&CONFIG.request_url,
			title = &CONFIG.title,
			magic_link = &magic_link,
			email = &user.email,
			name = name,
			username = username
		)?;
		let mut req = client.request(method, url);

		if let Some(data) = &CONFIG.request_data {
			let body = formatx!(
				data.as_str(),
				title = &CONFIG.title,
				magic_link = &magic_link,
				email = &user.email,
				name = name,
				username = username
			)?;
			req = req
				// TODO: Make this configurable
				.header(CONTENT_TYPE, "application/x-www-form-urlencoded")
				.body(body);
		}

		info!("Sending request for user {}", &user.email);
		let resp = req.send().await?;
		if !resp.status().is_success() {
			log::warn!("Request for user {} failed: {} {}", &user.email, resp.status(), resp.text().await.unwrap_or_default());
		}
	}

	if let Ok(scoped) = serde_qs::from_str::<ScopedLogin>(req.query_string()) {
		println!("Setting scoped login for link: {:?}", &scoped);
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
				.service(login_action)
		)
		.await;

		// Login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo { email: "valid@example.com".to_string() })
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);

		// Invalid login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo { email: "invalid@example.com".to_string() })
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);

		let links = MagicLinkToken::get_with_filter(|t| {
			t.user == "invalid@example.com"
		}, db).unwrap();
		assert!(links.is_empty());
	}
}
