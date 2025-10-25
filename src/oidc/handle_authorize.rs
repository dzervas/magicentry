use actix_web::cookie::{Cookie, SameSite};
use actix_web::dev::ConnectionInfo;
use actix_web::http::header::ContentType;
use actix_web::http::Uri;
use actix_web::{get, post, web, HttpResponse, Responder};
use tracing::info;

use crate::error::{OidcError, Response};
use anyhow::Context as _;
use crate::secret::{BrowserSessionSecret, OIDCAuthCodeSecret};
use crate::pages::{AuthorizePage, Page};
use crate::config::ConfigFile;
use crate::AUTHORIZATION_COOKIE;

use super::AuthorizeRequest;

async fn authorize(
	conn: ConnectionInfo,
	db: web::Data<crate::Database>,
	auth_req: AuthorizeRequest,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> Response {
	info!("Beginning OIDC flow for {}", auth_req.client_id);

	let Some(browser_session) = browser_session_opt else {
		let base_url = ConfigFile::url_from_request(conn).await;
		let mut target_url = url::Url::parse(&base_url).map_err(|_| OidcError::InvalidRedirectUrl)?;
		target_url.set_path("/login");
		target_url.query_pairs_mut()
			.append_pair("oidc", &serde_json::to_string(&auth_req)
				.with_context(|| format!("Failed to serialize OIDC auth request for client {}", auth_req.client_id))?);

		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url.as_str()))
			.finish());
	};

	let oidc_authcode = OIDCAuthCodeSecret::new_child(browser_session, auth_req.clone(), &db).await?;

	// TODO: Check the state with the cookie for CSRF
	// TODO: WTF?
	let redirect_url = auth_req
		.get_redirect_url(&oidc_authcode.code().to_str_that_i_wont_print(), oidc_authcode.user())
		.await
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_uri = redirect_url.parse::<Uri>()
			.context("Failed to parse redirect URL as URI")?;
	let redirect_url_scheme = redirect_url_uri
		.scheme_str()
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_authority = redirect_url_uri
		.authority()
		.ok_or(OidcError::InvalidRedirectUrl)?;
	let redirect_url_str = format!("{redirect_url_scheme}://{redirect_url_authority}");

	let authorize_page = AuthorizePage {
		client: redirect_url_str,
		name: oidc_authcode.user().name.clone(),
		username: oidc_authcode.user().username.clone(),
		email: oidc_authcode.user().email.clone(),
		saml_response_data: None,
		saml_relay_state: None,
		saml_acs: None,
		link: Some(redirect_url),
	}.render().await;

	let cookie = Cookie::build(AUTHORIZATION_COOKIE, serde_json::to_string(&auth_req)
			.with_context(|| format!("Failed to serialize OIDC auth request for cookie: {}", auth_req.client_id))?)
		.http_only(true)
		.same_site(SameSite::Lax)
		.path("/")
		.finish();

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.cookie(cookie)
		.body(authorize_page.into_string()))
	// Either send to ?code=<code>&state=<state>
	// TODO: Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/oidc/authorize")]
pub async fn authorize_get(
	conn: ConnectionInfo,
	db: web::Data<crate::Database>,
	data: web::Query<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(conn, db, data.into_inner(), browser_session_opt).await
}

#[post("/oidc/authorize")]
pub async fn authorize_post(
	conn: ConnectionInfo,
	db: web::Data<crate::Database>,
	data: web::Form<AuthorizeRequest>,
	browser_session_opt: Option<BrowserSessionSecret>,
) -> impl Responder {
	authorize(conn, db, data.into_inner(), browser_session_opt).await
}
