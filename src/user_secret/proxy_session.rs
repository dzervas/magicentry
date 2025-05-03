
use serde::{Deserialize, Serialize};

use super::browser_session::BrowserSessionSecretKind;
use super::secret::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata, EmptyMetadata};

#[derive(PartialEq, Serialize, Deserialize)]
pub struct ProxySessionSecretKind;

impl UserSecretKind for ProxySessionSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<BrowserSessionSecretKind, EmptyMetadata>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxySessionSecret = UserSecret<ProxySessionSecretKind>;
