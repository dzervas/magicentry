use actix_web::http::header;
use actix_web::{get, web, HttpResponse};
use tracing::info;

use crate::config::LiveConfig;
use crate::error::Response;
use crate::secret::{LoginLinkSecret, BrowserSessionSecret};

#[get("/login/{magic}")]
async fn magic_link(
	config: LiveConfig,
	login_secret: LoginLinkSecret,
	db: web::Data<crate::Database>,
) -> Response {
	info!("User {} logged in", &login_secret.user().email);
	let login_redirect_opt = login_secret.metadata().clone();
	let browser_session: BrowserSessionSecret = login_secret.exchange(&config, &db).await?;
	let cookie = (&browser_session).into();

	// Handle post-login redirect URLs from the cookie set by OIDC/SAML/auth-url
	// These can be configured through either the service.<name>.auth_url.origins, service.<name>.saml.redirect_urls or service.<name>.oidc.redirect_urls
	// redirect_url = login_secret.redirect_url(&db).await?;
	let redirect_url = if let Some(login_redirect) = login_redirect_opt {
		login_redirect.into_redirect_url(Some(browser_session), &config, &db).await?
	} else {
		"/".to_string()
	};

	Ok(HttpResponse::Found()
		.append_header((header::LOCATION, redirect_url))
		.cookie(cookie)
		.finish())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::utils::tests::*;

	use actix_web::http::StatusCode;
	use actix_web::{test as actix_test, App};

	#[actix_web::test]
	async fn test_login_link() {
		let config = crate::CONFIG.read().await.clone().into();
		let db = &db_connect().await;
		let user = get_valid_user().await;
		let app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(magic_link),
		)
		.await;

		let token = LoginLinkSecret::new(user, None, &config, db).await.unwrap();

		// Assuming a valid session exists in the database
		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code().to_str_that_i_wont_print()).as_str())
			.to_request();

		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/");

		// Assuming an invalid session
		let req = actix_test::TestRequest::get()
			.uri("/login/invalid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");

		// Re-test the used valid link
		let req = actix_test::TestRequest::get()
			.uri(format!("/login/{}", token.code().to_str_that_i_wont_print()).as_str())
			.to_request();

		let resp = actix_test::call_service(&app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
