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
	drop(config);

	let rp_origin = Url::parse("http://localhost:8080").expect("Invalid webauthn URL");
	WebauthnBuilder::new("localhost", &rp_origin)?
		.rp_name(&title)
		.build()
}
