use webauthn_rs::prelude::*;

use crate::CONFIG;

pub mod store;

pub mod handle_auth_start;
pub mod handle_auth_finish;
pub mod handle_reg_start;
pub mod handle_reg_finish;

pub const WEBAUTHN_COOKIE: &str = "webauthn_registration";

pub fn init() -> WebauthnResult<Webauthn> {
	let config = CONFIG.try_read().expect("Failed to lock config for reading during webauthn init");
	let title = config.title.clone();
	let external_url = config.external_url.clone();
	drop(config);

	let rp_origin = Url::parse(&external_url).expect("Invalid webauthn URL");
	WebauthnBuilder::new(&rp_origin.host().unwrap().to_string(), &rp_origin)?
		.rp_name(&title)
		.build()
}
