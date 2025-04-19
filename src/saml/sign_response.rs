
use base64::Engine;
use base64::engine::general_purpose;
use log::debug;
use quick_xml::se::to_string_with_root;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::sha2::Sha256;
use sha2::{Digest, Sha256 as Sha256Hasher};

use super::authn_response::*;
use crate::error::Result;

impl AuthnResponse {
	// This function inserts the XML Signature into a SAML Response XML string
	pub fn sign_saml_response(
		&mut self,
		private_key_pem: &str,
		certificate_pem: &str,
	) -> Result<()> {
		let cert_data = certificate_pem
		.lines()
		.filter(|line| !line.contains("BEGIN CERTIFICATE") && !line.contains("END CERTIFICATE"))
		.collect::<String>()
		.replace("\n", "");

		// Load private key
		let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
		.or_else(|_| RsaPrivateKey::from_pkcs1_pem(private_key_pem)).unwrap();

		// First, serialize the assertion without signature to calculate its digest
		let mut assertion_without_sig = self.assertion.clone();
		assertion_without_sig.signature = None; // Ensure no signature for digest calculation

		// Serialize to calculate digest
		let mut assertion_xml = to_string_with_root("saml:Assertion", &assertion_without_sig)?;
		assertion_xml = assertion_xml
			// Super ugly hack to get around the lack of canonicalization in rust
			// Using a quick_xml::Serializer::with_empty_elements() would fix this
			.replace("/></saml:SubjectConfirmation>", "></saml:SubjectConfirmationData></saml:SubjectConfirmation>");
		debug!("Assertion XML: {}", assertion_xml);

		// Calculate digest
		let digest_value = Self::compute_digest(&assertion_xml)?;

		// Create the SignedInfo element
		let reference_uri = format!("#{}", assertion_without_sig.id);
		let signed_info = SignedInfo {
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
		let signed_info_xml = to_string_with_root("ds:SignedInfo", &signed_info)?;
		debug!("SignedInfo XML: {}", signed_info_xml);

		// Sign the SignedInfo
		let signature_value = Self::sign_data(&private_key, &signed_info_xml)?;

		// Create full signature structure
		let signature = Signature {
			signed_info,
			signature_value,
			key_info: KeyInfo {
				x509_data: X509Data {
					x509_certificate: cert_data,
				},
			},
		};

		// Add signature to assertion
		self.assertion.signature = Some(signature);

		Ok(())
	}

	// Compute SHA-256 digest of the data and Base64 encode it
	fn compute_digest(xml: &str) -> Result<String> {
		let mut hasher = Sha256Hasher::new();
		hasher.update(xml.as_bytes());
		let result = hasher.finalize();
		Ok(general_purpose::STANDARD.encode(result))
	}

	// Sign data with RSA-SHA256 and Base64 encode the signature
	fn sign_data(private_key: &RsaPrivateKey, data: &str) -> Result<String> {
		use rsa::pkcs1v15::SigningKey;

		let signing_key = SigningKey::<Sha256>::new(private_key.clone());
		let signature = signing_key.sign(data.as_bytes());
		Ok(general_purpose::STANDARD.encode(signature.to_bytes()))
	}

}
