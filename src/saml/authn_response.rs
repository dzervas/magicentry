use log::debug;

use base64::engine::general_purpose;
use base64::Engine;
use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

use super::authn_request::AuthnRequest;
use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthnResponse {
	#[serde(rename = "@xmlns:samlp")]
	pub samlp_ns: String,
	#[serde(rename = "@Destination")]
	pub destination: Option<String>,
	#[serde(rename = "@ID")]
	pub id: String,
	#[serde(rename = "@InResponseTo")]
	pub in_response_to: String,
	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,
	#[serde(rename = "@Version")]
	pub version: String,
	#[serde(rename = "saml:Issuer")]
	pub issuer: Issuer,
	#[serde(rename = "ds:Signature")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<Signature>,
	#[serde(rename = "samlp:Status")]
	pub status: Status,
	#[serde(rename = "saml:Assertion")]
	pub assertion: Assertion,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Issuer {
	#[serde(rename = "@xmlns:saml")]
	pub saml_ns: String,
	#[serde(rename = "$value")]
	pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Status {
	#[serde(rename = "samlp:StatusCode")]
	pub status_code: StatusCode,
	#[serde(rename = "samlp:StatusMessage")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub status_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct StatusCode {
	#[serde(rename = "@Value")]
	pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Assertion {
	#[serde(rename = "@xmlns:saml")]
	pub saml_ns: String,
	#[serde(rename = "@ID")]
	pub id: String,
	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,
	#[serde(rename = "@Version")]
	pub version: String,
	#[serde(rename = "saml:Issuer")]
	pub issuer: String,
	#[serde(rename = "saml:Subject")]
	pub subject: Subject,
	#[serde(rename = "saml:Conditions")]
	pub conditions: Conditions,
	#[serde(rename = "saml:AuthnStatement")]
	pub authn_statement: AuthnStatement,
	#[serde(rename = "ds:Signature")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<Signature>,
	#[serde(rename = "saml:AttributeStatement")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub attribute_statement: Option<AttributeStatement>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Signature {
	// Basic structure for XML signature
	#[serde(rename = "@xmlns:ds")]
	pub ds_ns: String,
	#[serde(rename = "ds:SignedInfo")]
	pub signed_info: SignedInfo,
	#[serde(rename = "ds:SignatureValue")]
	pub signature_value: String,
	#[serde(rename = "ds:KeyInfo")]
	pub key_info: KeyInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignedInfo {
	#[serde(rename = "@xmlns:ds")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub ds_ns: Option<String>,
	#[serde(rename = "ds:CanonicalizationMethod")]
	pub canonicalization_method: CanonicalizationMethod,
	#[serde(rename = "ds:SignatureMethod")]
	pub signature_method: SignatureMethod,
	#[serde(rename = "ds:Reference")]
	pub reference: Reference,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CanonicalizationMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignatureMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Reference {
	#[serde(rename = "@URI")]
	pub uri: String,
	#[serde(rename = "ds:Transforms")]
	pub transforms: Transforms,
	#[serde(rename = "ds:DigestMethod")]
	pub digest_method: DigestMethod,
	#[serde(rename = "ds:DigestValue")]
	pub digest_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transforms {
	#[serde(rename = "ds:Transform")]
	pub transform: Vec<Transform>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transform {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DigestMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyInfo {
	#[serde(rename = "ds:X509Data")]
	pub x509_data: X509Data,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct X509Data {
	#[serde(rename = "ds:X509Certificate")]
	pub x509_certificate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Subject {
	#[serde(rename = "saml:NameID")]
	pub name_id: NameID,
	#[serde(rename = "saml:SubjectConfirmation")]
	pub subject_confirmation: SubjectConfirmation,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NameID {
	#[serde(rename = "@Format")]
	pub format: String,
	#[serde(rename = "$value")]
	pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubjectConfirmation {
	#[serde(rename = "@Method")]
	pub method: String,
	#[serde(rename = "saml:SubjectConfirmationData")]
	pub subject_confirmation_data: SubjectConfirmationData,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SubjectConfirmationData {
	#[serde(rename = "@InResponseTo")]
	pub in_response_to: String,
	#[serde(rename = "@NotOnOrAfter")]
	pub not_on_or_after: String,
	#[serde(rename = "@Recipient")]
	pub recipient: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Conditions {
	#[serde(rename = "@NotBefore")]
	pub not_before: String,
	#[serde(rename = "@NotOnOrAfter")]
	pub not_on_or_after: String,
	#[serde(rename = "saml:AudienceRestriction")]
	pub audience_restriction: AudienceRestriction,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AudienceRestriction {
	#[serde(rename = "saml:Audience")]
	pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthnStatement {
	#[serde(rename = "@AuthnInstant")]
	pub authn_instant: String,
	#[serde(rename = "@SessionIndex")]
	pub session_index: String,
	#[serde(rename = "saml:AuthnContext")]
	pub authn_context: AuthnContext,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthnContext {
	#[serde(rename = "saml:AuthnContextClassRef")]
	pub authn_context_class_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttributeStatement {
	#[serde(rename = "saml:Attribute")]
	pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Attribute {
	#[serde(rename = "@Name")]
	pub name: String,

	#[serde(rename = "@NameFormat")]
	pub name_format: Option<String>,

	#[serde(rename = "saml:AttributeValue")]
	pub attribute_values: Vec<AttributeValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AttributeValue {
	#[serde(rename = "$value")]
	pub value: String,
}

impl AuthnResponse {
	pub fn to_encoded_string(&self) -> Result<String> {
		let mut xml = String::new();
		let mut ser = quick_xml::se::Serializer::with_root(&mut xml, Some("samlp:Response")).unwrap();
		ser.expand_empty_elements(true);
		self.serialize(ser)?;

		debug!("SAML Response XML: {}", xml);

		let encoded_response = general_purpose::STANDARD.encode(xml);

		Ok(encoded_response.trim().to_string())
	}
}

impl AuthnRequest {
	pub fn to_response(&self, idp_metadata: &str, user_id: &str) -> AuthnResponse {
		let now = Utc::now();
		let expiry = now + chrono::Duration::hours(1);
		let response_id = format!("_resp-{}", Uuid::new_v4());
		let assertion_id = format!("_assert-{}", Uuid::new_v4());
		let session_id = format!("_session-{}", Uuid::new_v4());

		// let attributes: Vec<Attribute> = user_attributes.into_iter()
		// .map(|(name, values)| {
		// 	Attribute {
		// 		name,
		// 		name_format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".to_string()),
		// 		attribute_values: values
		// 		.into_iter()
		// 		.map(|v| AttributeValue { value: v })
		// 		.collect(),
		// 	}
		// })
		// .collect();
		let attributes = vec![]; // Placeholder for attributes


		AuthnResponse {
			samlp_ns: "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
			id: response_id,
			version: "2.0".to_string(),
			issue_instant: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
			destination: self.acs_url.clone(),
			in_response_to: self.id.clone(),
			issuer: Issuer {
				saml_ns: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
				name: idp_metadata.to_string()
			},
			signature: None, // Will be added later during XML signing
			status: Status {
				status_code: StatusCode { value: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string() },
				status_message: None,
			},
			assertion: Assertion {
				saml_ns: "urn:oasis:names:tc:SAML:2.0:assertion".to_string(),
				id: assertion_id,
				version: "2.0".to_string(),
				issue_instant: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
				issuer: idp_metadata.to_string(),
				signature: None, // Will be added later during XML signing
				subject: Subject {
					name_id: NameID {
						format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
						value: user_id.to_string(),
					},
					subject_confirmation: SubjectConfirmation {
						method: "urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string(),
						subject_confirmation_data: SubjectConfirmationData {
							not_on_or_after: expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
							recipient: self.acs_url.clone().unwrap(),
							in_response_to: self.id.clone(),
						},
					},
				},
				conditions: Conditions {
					not_before: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
					not_on_or_after: expiry.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
					audience_restriction: AudienceRestriction {
						audience: self.issuer.clone(),
					},
				},
				authn_statement: AuthnStatement {
					authn_instant: now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
					session_index: session_id,
					authn_context: AuthnContext {
						authn_context_class_ref: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password".to_string(),
					},
				},
				attribute_statement: if attributes.is_empty() {
					None
				} else {
					Some(AttributeStatement { attributes })
				},
			},
		}
	}
}
