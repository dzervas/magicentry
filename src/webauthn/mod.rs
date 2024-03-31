use webauthn_rs::prelude::*;

pub mod store;

pub mod handle_auth_start;
pub mod handle_auth_finish;
pub mod handle_reg_start;
pub mod handle_reg_finish;

pub const WEBAUTHN_COOKIE: &str = "webauthn_registration";

pub fn init(title: String, external_url: String) -> WebauthnResult<Webauthn> {
	let rp_origin = Url::parse(&external_url).expect("Invalid webauthn URL");
	WebauthnBuilder::new(&rp_origin.host().unwrap().to_string(), &rp_origin)?
		.rp_name(&title)
		.build()
}
