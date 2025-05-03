use serde::{Deserialize, Serialize};

use super::browser_session::BrowserSessionSecretKind;
use super::proxy_session::ProxySessionSecretKind;
use super::secret::{EphemeralUserSecret, UserSecretKind};
use super::{ChildSecretMetadata};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, url::Url>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxyCodeSecret = EphemeralUserSecret<ProxyCodeSecretKind, ProxySessionSecretKind>;
