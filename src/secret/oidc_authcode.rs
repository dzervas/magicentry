use serde::{Deserialize, Serialize};

use crate::oidc::authorize_request::AuthorizeRequest;

use super::browser_session::BrowserSessionSecretKind;
use super::ephemeral_primitive::EphemeralUserSecret;
use super::oidc_token::OIDCTokenSecretKind;
use super::primitive::UserSecretKind;
use super::ChildSecretMetadata;

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct OIDCAuthCodeSecretKind;

impl UserSecretKind for OIDCAuthCodeSecretKind {
	const PREFIX: &'static str = "oidc_authcode";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, AuthorizeRequest>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type OIDCAuthCodeSecret = EphemeralUserSecret<OIDCAuthCodeSecretKind, OIDCTokenSecretKind>;
