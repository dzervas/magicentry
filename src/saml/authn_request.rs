use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthnRequest {
	#[serde(rename = "@ID")]
	pub id: String,

	#[serde(rename = "@Version")]
	pub version: String,

	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,

	#[serde(rename = "@AssertionConsumerServiceURL")]
	pub acs_url: Option<String>,

	#[serde(rename = "@Destination")]
	pub destination: Option<String>,

	#[serde(rename = "@ForceAuthn")]
	pub force_authn: Option<bool>,

	#[serde(rename = "@IsPassive")]
	pub is_passive: Option<bool>,

	#[serde(rename = "@ProtocolBinding")]
	pub protocol_binding: Option<String>,

    #[serde(rename = "Issuer", default)]
	pub issuer: String,

    #[serde(rename = "NameIDPolicy")]
	pub name_id_policy: Option<NameIDPolicy>,

    #[serde(rename = "RequestedAuthnContext")]
	pub requested_authn_context: Option<RequestedAuthnContext>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NameIDPolicy {
	#[serde(rename = "@Format")]
	pub format: Option<String>,

	#[serde(rename = "@AllowCreate")]
	pub allow_create: Option<String>,

	#[serde(rename = "@SPNameQualifier")]
	pub sp_name_qualifier: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RequestedAuthnContext {
	#[serde(rename = "@Comparison")]
	pub comparison: Option<String>,

	#[serde(rename = "AuthnContextClassRef")]
	pub authn_context_class_ref: Vec<String>,
}
