use base64::{engine::general_purpose, Engine};
use flate2::read::DeflateDecoder;
use serde::{Deserialize, Serialize};
use std::io::Read;

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthnRequest {
	#[serde(rename = "@ID")]
	pub id: String,
	#[serde(rename = "@Version")]
	pub version: String,
	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,
	#[serde(rename = "@AssertionConsumerServiceURL")]
	pub acs_url: String,
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NameIDPolicy {
	#[serde(rename = "@Format")]
	pub format: Option<String>,
	#[serde(rename = "@AllowCreate")]
	pub allow_create: Option<String>,
	#[serde(rename = "@SPNameQualifier")]
	pub sp_name_qualifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RequestedAuthnContext {
	#[serde(rename = "@Comparison")]
	pub comparison: Option<String>,
	#[serde(rename = "AuthnContextClassRef")]
	pub authn_context_class_ref: Vec<String>,
}

impl AuthnRequest {
	pub fn from_encoded_string(encoded_request: &str) -> Result<Self> {
		let base64_decoded = general_purpose::STANDARD.decode(encoded_request)?;

		let mut decoder = DeflateDecoder::new(&base64_decoded[..]);
		let mut inflated_data = String::new();

		// Attempt to decompress
		let xml_str = if let Ok(_) = decoder.read_to_string(&mut inflated_data) {
			inflated_data
		} else {
			String::from_utf8(base64_decoded)?
		};

		Ok(quick_xml::de::from_str::<Self>(&xml_str)?)
	}
}
