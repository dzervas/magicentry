use serde::{Deserialize, Serialize};
use chrono::Utc;
use uuid::Uuid;

use super::authn_request::AuthnRequest;

#[derive(Debug, Serialize, Deserialize)]
pub struct SAMLResponse {
	#[serde(rename = "@ID")]
	pub id: String,

	#[serde(rename = "@Version")]
	pub version: String,

	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,

	#[serde(rename = "@Destination")]
	pub destination: Option<String>,

	#[serde(rename = "@InResponseTo")]
	pub in_response_to: String,

	#[serde(rename = "Issuer", alias = "saml:Issuer", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")]
	pub issuer: String,

	#[serde(rename = "Status", alias = "samlp:Status", alias = "{urn:oasis:names:tc:SAML:2.0:protocol}Status")]
	pub status: Status,

	#[serde(rename = "Assertion", alias = "saml:Assertion", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")]
	pub assertion: Assertion,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Status {
	#[serde(rename = "StatusCode", alias = "samlp:StatusCode", alias = "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")]
	pub status_code: StatusCode,

	#[serde(rename = "StatusMessage", alias = "samlp:StatusMessage", alias = "{urn:oasis:names:tc:SAML:2.0:protocol}StatusMessage")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub status_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusCode {
	#[serde(rename = "@Value")]
	pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assertion {
	#[serde(rename = "@ID")]
	pub id: String,

	#[serde(rename = "@Version")]
	pub version: String,

	#[serde(rename = "@IssueInstant")]
	pub issue_instant: String,

	#[serde(rename = "Issuer", alias = "saml:Issuer", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")]
	pub issuer: String,

	#[serde(rename = "Signature", alias = "ds:Signature", alias = "{http://www.w3.org/2000/09/xmldsig#}Signature")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub signature: Option<Signature>,

	#[serde(rename = "Subject", alias = "saml:Subject", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")]
	pub subject: Subject,

	#[serde(rename = "Conditions", alias = "saml:Conditions", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")]
	pub conditions: Conditions,

	#[serde(rename = "AuthnStatement", alias = "saml:AuthnStatement", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement")]
	pub authn_statement: AuthnStatement,

	#[serde(rename = "AttributeStatement", alias = "saml:AttributeStatement", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement")]
	#[serde(skip_serializing_if = "Option::is_none")]
	pub attribute_statement: Option<AttributeStatement>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Signature {
	// Basic structure for XML signature
	#[serde(rename = "SignedInfo", alias = "ds:SignedInfo", alias = "{http://www.w3.org/2000/09/xmldsig#}SignedInfo")]
	pub signed_info: SignedInfo,

	#[serde(rename = "SignatureValue", alias = "ds:SignatureValue", alias = "{http://www.w3.org/2000/09/xmldsig#}SignatureValue")]
	pub signature_value: String,

	#[serde(rename = "KeyInfo", alias = "ds:KeyInfo", alias = "{http://www.w3.org/2000/09/xmldsig#}KeyInfo")]
	pub key_info: KeyInfo,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedInfo {
	#[serde(rename = "CanonicalizationMethod", alias = "ds:CanonicalizationMethod", alias = "{http://www.w3.org/2000/09/xmldsig#}CanonicalizationMethod")]
	pub canonicalization_method: CanonicalizationMethod,

	#[serde(rename = "SignatureMethod", alias = "ds:SignatureMethod", alias = "{http://www.w3.org/2000/09/xmldsig#}SignatureMethod")]
	pub signature_method: SignatureMethod,

	#[serde(rename = "Reference", alias = "ds:Reference", alias = "{http://www.w3.org/2000/09/xmldsig#}Reference")]
	pub reference: Reference,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CanonicalizationMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Reference {
	#[serde(rename = "@URI")]
	pub uri: String,

	#[serde(rename = "Transforms", alias = "ds:Transforms", alias = "{http://www.w3.org/2000/09/xmldsig#}Transforms")]
	pub transforms: Transforms,

	#[serde(rename = "DigestMethod", alias = "ds:DigestMethod", alias = "{http://www.w3.org/2000/09/xmldsig#}DigestMethod")]
	pub digest_method: DigestMethod,

	#[serde(rename = "DigestValue", alias = "ds:DigestValue", alias = "{http://www.w3.org/2000/09/xmldsig#}DigestValue")]
	pub digest_value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transforms {
	#[serde(rename = "Transform", alias = "ds:Transform", alias = "{http://www.w3.org/2000/09/xmldsig#}Transform")]
	pub transform: Vec<Transform>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Transform {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DigestMethod {
	#[serde(rename = "@Algorithm")]
	pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyInfo {
	#[serde(rename = "X509Data", alias = "ds:X509Data", alias = "{http://www.w3.org/2000/09/xmldsig#}X509Data")]
	pub x509_data: X509Data,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct X509Data {
	#[serde(rename = "X509Certificate", alias = "ds:X509Certificate", alias = "{http://www.w3.org/2000/09/xmldsig#}X509Certificate")]
	pub x509_certificate: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Subject {
	#[serde(rename = "NameID", alias = "saml:NameID", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")]
	pub name_id: NameID,

	#[serde(rename = "SubjectConfirmation", alias = "saml:SubjectConfirmation", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation")]
	pub subject_confirmation: SubjectConfirmation,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NameID {
	#[serde(rename = "@Format")]
	pub format: String,

	#[serde(rename = "$value")]
	pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubjectConfirmation {
	#[serde(rename = "@Method")]
	pub method: String,

	#[serde(rename = "SubjectConfirmationData", alias = "saml:SubjectConfirmationData", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData")]
	pub subject_confirmation_data: SubjectConfirmationData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubjectConfirmationData {
	#[serde(rename = "@NotOnOrAfter")]
	pub not_on_or_after: String,

	#[serde(rename = "@Recipient")]
	pub recipient: String,

	#[serde(rename = "@InResponseTo")]
	pub in_response_to: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Conditions {
	#[serde(rename = "@NotBefore")]
	pub not_before: String,

	#[serde(rename = "@NotOnOrAfter")]
	pub not_on_or_after: String,

	#[serde(rename = "AudienceRestriction", alias = "saml:AudienceRestriction", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction")]
	pub audience_restriction: AudienceRestriction,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AudienceRestriction {
	#[serde(rename = "Audience", alias = "saml:Audience", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Audience")]
	pub audience: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthnStatement {
	#[serde(rename = "@AuthnInstant")]
	pub authn_instant: String,

	#[serde(rename = "@SessionIndex")]
	pub session_index: String,

	#[serde(rename = "AuthnContext", alias = "saml:AuthnContext", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContext")]
	pub authn_context: AuthnContext,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthnContext {
	#[serde(rename = "AuthnContextClassRef", alias = "saml:AuthnContextClassRef", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef")]
	pub authn_context_class_ref: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttributeStatement {
	#[serde(rename = "Attribute", alias = "saml:Attribute", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute")]
	pub attributes: Vec<Attribute>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Attribute {
	#[serde(rename = "@Name")]
	pub name: String,

	#[serde(rename = "@NameFormat")]
	pub name_format: Option<String>,

	#[serde(rename = "AttributeValue", alias = "saml:AttributeValue", alias = "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue")]
	pub attribute_values: Vec<AttributeValue>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AttributeValue {
	#[serde(rename = "$value")]
	pub value: String,
}

impl AuthnRequest {
	pub fn to_response(&self, idp_metadata: &str, user_id: &str) -> SAMLResponse {
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


		SAMLResponse {
			id: response_id,
			version: "2.0".to_string(),
			issue_instant: now.to_rfc3339(),
			destination: self.acs_url.clone(),
			in_response_to: self.id.clone(),
			issuer: idp_metadata.to_string(),
			status: Status {
				status_code: StatusCode { value: "urn:oasis:names:tc:SAML:2.0:status:Success".to_string() },
				status_message: None,
			},
			assertion: Assertion {
				id: assertion_id,
				version: "2.0".to_string(),
				issue_instant: now.to_rfc3339(),
				issuer: idp_metadata.to_string(),
				signature: None, // Will be added later during XML signing
				subject: Subject {
					name_id: NameID {
						format: "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".to_string(),
						value: user_id.to_string(),
					},
					subject_confirmation: SubjectConfirmation {
						method: "urn:oasis:names:tc:SAML:2.0:cm:bearer".to_string(),
						subject_confirmation_data: SubjectConfirmationData {
							not_on_or_after: expiry.to_rfc3339(),
							recipient: self.acs_url.clone().unwrap(),
							in_response_to: self.id.clone(),
						},
					},
				},
				conditions: Conditions {
					not_before: now.to_rfc3339(),
					not_on_or_after: expiry.to_rfc3339(),
					audience_restriction: AudienceRestriction {
						audience: self.issuer.clone(),
					},
				},
				authn_statement: AuthnStatement {
					authn_instant: now.to_rfc3339(),
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
