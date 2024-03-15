use actix_web::{post, web, HttpRequest, HttpResponse};
use formatx::formatx;
use lettre::AsyncTransport;
use log::info;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use crate::error::Response;
use crate::user::{User, UserLink};
use crate::{SmtpTransport, CONFIG};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct LoginInfo {
	email: String,
}

#[post("/login")]
async fn login_action(req: HttpRequest, form: web::Form<LoginInfo>, db: web::Data<SqlitePool>, mailer: web::Data<Option<SmtpTransport>>, http_client: web::Data<Option<reqwest::Client>>) -> Response {
	let user = if let Some(user) = User::from_config(&form.email) {
		user
	} else {
		// Return 200 to avoid leaking valid emails
		return Ok(HttpResponse::Ok().finish())
	};

	let link = UserLink::new(&db, user.email.clone()).await?;
	let base_url = CONFIG.url_from_request(&req);
	let magic_link = format!("{}login/{}", base_url, link.magic);
	let name = &user.name.unwrap_or_default();
	let username = &user.username.unwrap_or_default();

	#[cfg(debug_assertions)]
	println!("Link: {} {:?}", &magic_link, link);

	if let Some(mailer) = mailer.as_ref() {
		let email = lettre::Message::builder()
			.from(CONFIG.smtp_from.parse()?)
			.to(user.email.parse()?)
			.subject(formatx!(&CONFIG.smtp_subject, title = &CONFIG.title)?)
			.body(formatx!(
				&CONFIG.smtp_body,
				link = &magic_link,
				name = name,
				username = username
			)?)?;

		info!("Sending email to {}", &user.email);
		mailer.send(email).await?;
	}

	if let Some(client) = http_client.as_ref() {
		let method = reqwest::Method::from_bytes(CONFIG.request_method.as_bytes()).unwrap();
		let url = formatx!(
			&CONFIG.request_url,
			title = &CONFIG.title,
			link = &magic_link,
			email = &link.email,
			name = name,
			username = username
		)?;
		let mut req = client.request(method, url);

		if let Some(data) = &CONFIG.request_data {
			let body = formatx!(
				data.as_str(),
				title = &CONFIG.title,
				link = &magic_link,
				email = &link.email,
				name = name,
				username = username
			)?;
			req = req.body(body);
		}

		info!("Sending request for user {}", &user.email);
		req.send().await?;
	}

	Ok(HttpResponse::Ok().finish())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::tests::*;

	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};
	use sqlx::query;

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

		let links = query!("SELECT * FROM links WHERE email = 'invalid@example.com'")
			.fetch_optional(db)
			.await
			.unwrap();
		assert!(links.is_none());
	}
}
