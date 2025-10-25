use actix_web::{get, HttpResponse};
use anyhow::Context as _;
use serde::Serialize;

use crate::config::LiveConfig;
use crate::error::Response;

use super::entity_descriptor::EntityDescriptor;


#[get("/saml/metadata")]
pub async fn metadata(config: LiveConfig) -> Response {
	let external_url = config.external_url.clone();
	let cert_x509 = config.get_saml_cert()
		.context("Failed to get SAML certificate from configuration")?;

	let discovery = EntityDescriptor::new(&external_url, &cert_x509);

	let mut discovery_xml = String::new();
	let mut ser = quick_xml::se::Serializer::with_root(&mut discovery_xml, Some("md:EntityDescriptor"))
		.context("Failed to create XML serializer for SAML metadata")?;
	ser.expand_empty_elements(true);
	discovery.serialize(ser)
		.context("Failed to serialize SAML metadata to XML")?;

	Ok(HttpResponse::Ok()
		.append_header(("Content-Type", "application/xml"))
		.body(discovery_xml))
}
