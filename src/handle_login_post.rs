//! The login form submission handler - used to handle the login form
//! showed by the [handle_login](crate::handle_login) endpoint
//!
//! It handles the magic link generation, sending it to the user (email/webhook)
//! and saving any redirection-related data so that when the user clicks the link,
//! they can be redirected to the right place - used for auth-url/OIDC/SAML
//!
//!
//!
//! <span class="warning">
//! WARNING:
//! When the <span class="stab">e2e-test</span> feature is enabled,
//! the magic link will be saved to a file in the `hurl` directory,
//!
//! so that it can be used for end-to-end testing purposes
//! </span>

use std::collections::BTreeMap;

use actix_web::http::header::ContentType;
use actix_web::{post, web, HttpRequest, HttpResponse};
use formatx::formatx;
use lettre::message::header::ContentType as LettreContentType;
use lettre::{AsyncTransport, Message};
use log::info;
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};

use crate::error::Response;
use crate::user::User;
use crate::secret::login_link::LoginLinkRedirect;
use crate::secret::LoginLinkSecret;
use crate::utils::get_partial;
use crate::{SmtpTransport, CONFIG};

#[cfg(feature = "e2e-test")]
use std::io::Write;

/// Used to get the login form data for from the login page
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LoginInfo {
	pub email: String,
}

#[post("/login")]
async fn login_post(
	req: HttpRequest,
	web::Form(form): web::Form<LoginInfo>,
	web::Query(login_redirect): web::Query<LoginLinkRedirect>,
	db: web::Data<crate::Database>,
	mailer: web::Data<Option<SmtpTransport>>,
	http_client: web::Data<Option<reqwest::Client>>,
) -> Response {
	let login_action_page = get_partial::<()>("login_action", BTreeMap::new(), None)?;
	let result = Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_action_page));

	// Return 200 to avoid leaking valid emails
	let Some(user) = User::from_email(&form.email).await else {
		return result;
	};

	// Generate the magic link
	let link = LoginLinkSecret::new(
		user.clone(),
		login_redirect.into_opt().await,
		&db
	).await?;
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
	// TODO: Make a notifier struct that is `FromRequest` (`FromConfig`?)
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
				.service(login_post),
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
