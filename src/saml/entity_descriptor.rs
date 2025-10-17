use serde::{Deserialize, Serialize};

use super::authn_response::{KeyInfo, X509Data};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EntityDescriptor {
	#[serde(rename = "@xmlns:md")]
	pub md_ns: String,
	#[serde(rename = "@validUntil")]
	pub valid_until: String,
	#[serde(rename = "@cacheDuration")]
	pub cache_duration: String,
	#[serde(rename = "@entityID")]
	pub entity_id: String,
	#[serde(rename = "md:IDPSSODescriptor")]
	pub id_descriptor: IDPSSODescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IDPSSODescriptor {
	#[serde(rename = "@WantAuthnRequestsSigned")]
	pub require_signed_requests: String,
	#[serde(rename = "@protocolSupportEnumeration")]
	pub protocol_support: String,
	#[serde(rename = "md:KeyDescriptor")]
	pub key_descriptors: Vec<KeyDescriptor>,
	#[serde(rename = "md:SingleLogoutService")]
	pub logout_service: Service,
	#[serde(rename = "md:NameIDFormat")]
	pub name_id_format: String,
	#[serde(rename = "md:SingleSignOnService")]
	pub sso_service: Service,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyDescriptor {
	#[serde(rename = "@use")]
	pub usage: String,
	#[serde(rename = "ds:KeyInfo")]
	pub key_info: KeyInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Service {
	#[serde(rename = "@Binding")]
	pub binding: String,
	#[serde(rename = "@Location")]
	pub location: String,
}

impl EntityDescriptor {
	#[must_use]
	pub fn new(host: &str, public_key: &str) -> Self {
		let now = chrono::Utc::now();

		Self {
			md_ns: "urn:oasis:names:tc:SAML:2.0:metadata".to_string(),
			valid_until: (now + chrono::Duration::days(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
			cache_duration: "PT1440M".to_string(),
			entity_id: format!("{host}/saml/metadata"),
			id_descriptor: IDPSSODescriptor {
				require_signed_requests: "false".to_string(),
				protocol_support: "urn:oasis:names:tc:SAML:2.0:protocol".to_string(),
				name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
				sso_service: Service {
					binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".to_string(),
					location: format!("{host}/saml/sso"),
				},
				logout_service: Service {
					binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".to_string(),
					location: format!("{host}/saml/logout"),
				},
				key_descriptors: vec![KeyDescriptor {
					usage: "signing".to_string(),
					key_info: KeyInfo {
						ds_ns: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
						x509_data: X509Data {
							x509_certificate: public_key.to_string(),
						},
					},
				}],
			},
		}
	}
}
