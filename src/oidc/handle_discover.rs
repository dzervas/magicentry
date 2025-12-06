use serde::{Serialize, Serializer};

// use crate::generate_cors_preflight;
use crate::config::LiveConfig;

// Serialize a vector of strings as a space-separated string
#[allow(clippy::ptr_arg)]
fn serialize_vec_with_space<S: Serializer>(
	vec: &Vec<&str>,
	serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
	serializer.serialize_str(&vec.join(" "))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Discovery<'a> {
	pub issuer: String,

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
	pub token_endpoint_auth_methods_supported: Vec<&'a str>,
	pub claims_supported: Vec<&'a str>,

	pub subject_types_supported: Vec<&'a str>,
}

impl<'a> Discovery<'a> {
	#[must_use]
	pub fn new(base: String, external_url: String) -> Self {
		Discovery {
			issuer: base.clone(),

			authorization_endpoint: format!("{external_url}/oidc/authorize"),
			token_endpoint: format!("{base}/oidc/token"),
			userinfo_endpoint: format!("{base}/oidc/userinfo"),
			end_session_endpoint: format!("{external_url}/logout"),
			jwks_uri: format!("{base}/oidc/jwks"),

			scopes_supported: vec!["openid", "profile", "email"],
			response_types_supported: vec!["code", "id_token", "id_token token"],
			id_token_signing_alg_values_supported: vec!["RS256"],
			userinfo_signing_alg_values_supported: vec!["none"],
			token_endpoint_auth_methods_supported: vec![
				"client_secret_post",
				"client_secret_basic",
			],
			claims_supported: vec![
				"sub",
				"email",
				"preferred_username",
				"name",
				"nickname",
				"email_verified",
			],

			// Pairwise would require a different username per client, too much hassle
			subject_types_supported: vec!["public"],
		}
	}
}

// generate_cors_preflight!(
// 	discover_preflight,
// 	"/.well-known/openid-configuration",
// 	"GET"
// );

#[axum::debug_handler]
pub async fn handle_discover(
	config: LiveConfig,
	axum::extract::State(_state): axum::extract::State<crate::AppState>,
	axum_extra::extract::Host(host): axum_extra::extract::Host,
) -> impl axum::response::IntoResponse {
	let discovery = Discovery::new(host, config.external_url.clone());

	(
		[
			("Access-Control-Allow-Origin", "*"),
			("Access-Control-Allow-Methods", "GET, OPTIONS"),
			("Access-Control-Allow-Headers", "Content-Type"),
		],
		axum::Json(discovery),
	)
}
