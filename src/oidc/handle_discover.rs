use serde::{Serialize, Serializer};
use actix_web::{get, HttpRequest, HttpResponse, Responder};

use crate::CONFIG;

fn serialize_vec_with_space<S: Serializer>(vec: &Vec<&str>, serializer: S) -> std::result::Result<S::Ok, S::Error> {
	serializer.serialize_str(&vec.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Discovery<'a> {
	pub issuer: &'a str,

	// These are String because they get constructed with format!
	pub authorization_endpoint: String,
	pub token_endpoint: String,
	pub userinfo_endpoint: String,
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
	pub fn new(base: &'a str) -> Self {
		Discovery {
			issuer: base,

			authorization_endpoint: format!("{}/oidc/authorize", base),
			token_endpoint: format!("{}/oidc/token", base),
			userinfo_endpoint: format!("{}/oidc/userinfo", base),
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
	let discovery = Discovery::new(&base_url);
	HttpResponse::Ok().json(discovery)
}
