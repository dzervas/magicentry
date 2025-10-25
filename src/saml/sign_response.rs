
use base64::Engine;
use base64::engine::general_purpose;
use tracing::debug;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::sha2::Sha256;
use sha2::{Digest, Sha256 as Sha256Hasher};
use serde::Serialize;

#[allow(clippy::wildcard_imports)]
use super::authn_response::*;
use anyhow::Result;

impl AuthnResponse {
	// This function inserts the XML Signature into a SAML Response XML string
	pub fn sign_saml_response(
		&mut self,
		private_key_x509: &str,
		certificate_x509: &str,
	) -> Result<()> {
		let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_x509)
		.or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_x509))?;

		// Serialize to calculate digest
		let mut xml = String::new();
		let mut ser = quick_xml::se::Serializer::with_root(&mut xml, Some("samlp:Response"))?;
		ser.expand_empty_elements(true);
		self.serialize(ser)?;

		// Calculate digest
		let digest_value = Self::compute_digest(&xml);

		// Create the SignedInfo element
		let reference_uri = format!("#{}", self.id);
		let mut signed_info = SignedInfo {
			ds_ns: Some("http://www.w3.org/2000/09/xmldsig#".to_string()),
			canonicalization_method: CanonicalizationMethod {
				algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string(),
			},
			signature_method: SignatureMethod {
				algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256".to_string(),
			},
			reference: Reference {
				uri: reference_uri,
				transforms: Transforms {
					transform: vec![
					Transform { algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature".to_string() },
					Transform { algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#".to_string() },
					],
				},
				digest_method: DigestMethod {
					algorithm: "http://www.w3.org/2001/04/xmlenc#sha256".to_string(),
				},
				digest_value,
			},
		};

		// Serialize SignedInfo to XML for signing
		let mut signed_info_xml = String::new();
		let mut ser = quick_xml::se::Serializer::with_root(&mut signed_info_xml, Some("ds:SignedInfo"))?;
		ser.expand_empty_elements(true);
		signed_info.serialize(ser)?;
		debug!("SignedInfo XML: {signed_info_xml}");

		signed_info.ds_ns = None; // Remove the namespace after signing - Signature has it already

		// Sign the SignedInfo
		let signature_value = Self::sign_data(&private_key, &signed_info_xml);

		// Create full signature structure
		let signature = Signature {
			ds_ns: "http://www.w3.org/2000/09/xmldsig#".to_string(),
			signed_info,
			signature_value,
			key_info: KeyInfo {
				ds_ns: None,
				x509_data: X509Data {
					x509_certificate: certificate_x509.to_string(),
				},
			},
		};

		// Add signature to assertion
		self.signature = Some(signature);

		Ok(())
	}

	// Compute SHA-256 digest of the data and Base64 encode it
	fn compute_digest(xml: &str) -> String {
		let mut hasher = Sha256Hasher::new();
		hasher.update(xml.as_bytes());
		let result = hasher.finalize();
		general_purpose::STANDARD.encode(result)
	}

	// Sign data with RSA-SHA256 and Base64 encode the signature
	fn sign_data(private_key: &RsaPrivateKey, data: &str) -> String {
		use rsa::pkcs1v15::SigningKey;

		let signing_key = SigningKey::<Sha256>::new(private_key.clone());
		let signature = signing_key.sign(data.as_bytes());
		general_purpose::STANDARD.encode(signature.to_bytes())
	}

}
