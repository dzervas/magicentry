use actix_web::{get, options, HttpRequest, HttpResponse, Responder};
use serde::{Serialize, Serializer};

use crate::CONFIG;

fn serialize_vec_with_space<S: Serializer>(
	vec: &Vec<&str>,
	serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
	serializer.serialize_str(&vec.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Discovery<'a> {
	pub issuer: &'a str,

	// These are String because they get constructed with format!
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub userinfo_endpoint: String,
	pub end_session_endpoint: String,
	// TODO: check_session_iframe
	pub jwks_uri: String,

	#[serde(serialize_with = "serialize_vec_with_space")]
	pub scopes_supported: Vec<&'a str>,
	pub response_types_supported: Vec<&'a str>,
	pub id_token_signing_alg_values_supported: Vec<&'a str>,
	pub userinfo_signing_alg_values_supported: Vec<&'a str>,
	// pub token_endpoint_auth_methods_supported: Vec<&'a str>,
	pub claims_supported: Vec<&'a str>,

	pub subject_types_supported: Vec<&'a str>,
}

impl<'a> Discovery<'a> {
	pub async fn new(base: &'a str, external_url: &'a str) -> Self {
		Discovery {
			issuer: base,

			authorization_endpoint: format!("{}/oidc/authorize", external_url),
			token_endpoint: format!("{}/oidc/token", base),
			userinfo_endpoint: format!("{}/oidc/userinfo", base),
			end_session_endpoint: format!("{}/logout", external_url),
			jwks_uri: format!("{}/oidc/jwks", base),

			scopes_supported: vec!["openid", "profile", "email"],
			response_types_supported: vec!["code", "id_token", "id_token token"],
			id_token_signing_alg_values_supported: vec!["RS256"],
			userinfo_signing_alg_values_supported: vec!["none"],
			claims_supported: vec!["sub", "email", "preferred_username", "name"],

			// Pairwise would require a different username per client, too much hassle
			subject_types_supported: vec!["public"],
		}
	}
}

#[get("/.well-known/openid-configuration")]
pub async fn discover(req: HttpRequest) -> impl Responder {
	let config = CONFIG.read().await;
	let base_url = config.url_from_request(&req);
	let external_url = config.external_url.clone();
	let discovery = Discovery::new(&base_url, &external_url).await;
	HttpResponse::Ok()
		.append_header(("Access-Control-Allow-Origin", "*"))
		.append_header(("Access-Control-Allow-Methods", "GET, OPTIONS"))
		.append_header(("Access-Control-Allow-Headers", "Content-Type"))
		.json(discovery)
}

#[options("/.well-known/openid-configuration")]
pub async fn discover_preflight() -> impl Responder {
	HttpResponse::NoContent()
		.append_header(("Access-Control-Allow-Origin", "*"))
		.append_header(("Access-Control-Allow-Methods", "GET, OPTIONS"))
		.append_header(("Access-Control-Allow-Headers", "Content-Type"))
		.finish()
}
