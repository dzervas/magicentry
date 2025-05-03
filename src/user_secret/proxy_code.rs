use serde::{Deserialize, Serialize};

use super::browser_session::BrowserSessionSecretKind;
use super::proxy_session::ProxySessionSecretKind;
use super::secret::{UserSecret, UserSecretKind, UserSecretKindEphemeral};
use super::{ChildSecretMetadata};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, url::Url>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

impl UserSecretKindEphemeral for ProxyCodeSecretKind {
	type ExchangeTo = ProxySessionSecretKind;
}

pub type ProxyCodeSecret = UserSecret<ProxyCodeSecretKind>;
