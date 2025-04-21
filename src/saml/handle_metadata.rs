use actix_web::{get, HttpResponse};
use serde::Serialize;

use crate::error::Response;
use crate::CONFIG;

use super::entity_descriptor::EntityDescriptor;


#[get("/saml/metadata")]
pub async fn metadata() -> Response {
	let config = CONFIG.read().await;
	let external_url = config.external_url.clone();
	let cert_x509 = config.get_saml_cert()?;

	let discovery = EntityDescriptor::new(&external_url, &cert_x509);

	let mut discovery_xml = String::new();
	let mut ser = quick_xml::se::Serializer::with_root(&mut discovery_xml, Some("md:EntityDescriptor")).unwrap();
	ser.expand_empty_elements(true);
	discovery.serialize(ser).unwrap();

	Ok(HttpResponse::Ok()
		.append_header(("Content-Type", "application/xml"))
		.body(discovery_xml))
}
