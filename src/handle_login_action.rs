use std::collections::BTreeMap;
use std::io::Write;

use actix_session::Session;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::{post, web, HttpRequest, HttpResponse};
use formatx::formatx;
use lettre::message::header::ContentType as LettreContentType;
use lettre::{AsyncTransport, Message};
use log::{debug, info};
use reqwest::header::CONTENT_TYPE;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::user::User;
use crate::user_secret::LoginLinkSecret;
use crate::utils::get_partial;
use crate::{SmtpTransport, CONFIG, SCOPED_LOGIN};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LoginInfo {
	pub email: String,
}

/// This struct holds the `rd` query parameter, used by nginx at least
/// during handling of unauthenticated requests while using the auth-url
/// mechanism.
/// It is used to redirect the user back to the original URL after
/// authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyRedirectLink {
	#[serde(rename = "rd")]
	pub(crate) scope_app_url: String,
}

impl ProxyRedirectLink {
	pub async fn get_redirect_url(&self, code: &str, user: &User) -> Option<String> {
		let redirect_url = urlencoding::decode(&self.scope_app_url).ok()?.to_string();
		let redirect_url_clean = redirect_url.split("?").next()?.trim_end_matches('/');
		let redirect_url_parsed = redirect_url_clean.parse::<Uri>().ok()?;

		let origin_authority = redirect_url_parsed.authority()?;
		let origin_scheme = redirect_url_parsed.scheme()?;
		let origin = format!("{}://{}", origin_scheme, origin_authority);

		let config = CONFIG.read().await;
		// Check that the redirect URL is allowed and that the user has access to it
		config.services.from_origin_with_realms(&origin, user)?;

		let new_redirect_url = Url::parse_with_params(&redirect_url, &[("code", code)])
			.ok()?
			.to_string();

		Some(new_redirect_url)
	}
}

impl From<String> for ProxyRedirectLink {
	fn from(scope: String) -> Self {
		ProxyRedirectLink { scope_app_url: scope }
	}
}

impl From<ProxyRedirectLink> for String {
	fn from(scoped: ProxyRedirectLink) -> Self {
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
	let login_action_page = get_partial::<()>("login_action", BTreeMap::new(), None)?;
	let result = Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_action_page));

	// Return 200 to avoid leaking valid emails
	let Some(user) = User::from_config(&form.email).await else {
		return result;
	};

	// Generate the magic link
	let link = LoginLinkSecret::new(user.clone(), None, &db).await?;
	let config = CONFIG.read().await;
	let base_url = config.url_from_request(&req);
	let magic_link = base_url + &link.get_login_url();
	let name = &user.name.clone();
	let username = &user.username.clone();

	#[cfg(debug_assertions)]
	info!("Link: {}", &magic_link);

	#[cfg(feature = "e2e-test")]
	std::fs::File::create("hurl/.link.txt").unwrap().write_all(magic_link.as_bytes()).unwrap();

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
	if let Ok(scoped) = serde_qs::from_str::<ProxyRedirectLink>(req.query_string()) {
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

		// TODO: Test the login link
	}
}
