use actix_web::{get, HttpResponse, Responder};
use serde::Serialize;

use crate::CONFIG;

use super::entity_descriptor::EntityDescriptor;


#[get("/saml/metadata")]
pub async fn metadata() -> impl Responder {
	let config = CONFIG.read().await;
	let external_url = config.external_url.clone();
	let discovery = EntityDescriptor::new(&external_url, "test");

	let mut discovery_xml = String::new();
	let mut ser = quick_xml::se::Serializer::with_root(&mut discovery_xml, Some("md:EntityDescriptor")).unwrap();
	ser.expand_empty_elements(true);
	discovery.serialize(ser).unwrap();

	HttpResponse::Ok()
		.append_header(("Access-Control-Allow-Origin", "*"))
		.append_header(("Access-Control-Allow-Methods", "GET, OPTIONS"))
		.append_header(("Access-Control-Allow-Headers", "Content-Type"))
		.append_header(("Content-Type", "application/xml"))
		.body(discovery_xml)
}
