use tracing::info;
use webauthn_rs::prelude::*;

pub mod store;

pub mod handle_auth_finish;
pub mod handle_auth_start;
pub mod handle_reg_finish;
pub mod handle_reg_start;

pub const WEBAUTHN_AUTH_COOKIE: &str = "webauthn_authentication";
pub const WEBAUTHN_REG_COOKIE: &str = "webauthn_registration";

pub fn init(title: &str, external_url: &str) -> WebauthnResult<Webauthn> {
	let rp_origin = Url::parse(external_url).expect("Invalid webauthn URL");
	info!("Webauthn Origin: {rp_origin}");
	let rp_host = rp_origin.host().expect("Webauthn host extraction failed").to_string();
	WebauthnBuilder::new(&rp_host, &rp_origin)?
		.rp_name(title)
		.build()
}
