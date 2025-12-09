use anyhow::Context as _;
use axum::extract::State;
use axum::response::IntoResponse;
use serde::Serialize;

use crate::config::LiveConfig;
use crate::error::AppError;

use super::entity_descriptor::EntityDescriptor;

#[axum::debug_handler]
pub async fn handle_metadata(
	config: LiveConfig,
	State(_state): State<crate::AppState>,
) -> Result<impl IntoResponse, AppError> {
	let external_url = config.external_url.clone();
	let cert_x509 = config
		.get_saml_cert()
		.context("Failed to get SAML certificate from configuration")?;

	let discovery = EntityDescriptor::new(&external_url, &cert_x509);

	let mut discovery_xml = String::new();
	let mut ser =
		quick_xml::se::Serializer::with_root(&mut discovery_xml, Some("md:EntityDescriptor"))
			.context("Failed to create XML serializer for SAML metadata")?;
	ser.expand_empty_elements(true);
	discovery
		.serialize(ser)
		.context("Failed to serialize SAML metadata to XML")?;

	Ok((
		[(axum::http::header::CONTENT_TYPE, "application/xml")],
		discovery_xml,
	))
}
