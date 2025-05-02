use super::secret::{UserSecret, UserSecretKind};
use super::{ChildSecretMetadata};

pub struct ProxyCodeSecretKind;

impl UserSecretKind for ProxyCodeSecretKind {
	const PREFIX: &'static str = "proxy";
	type Metadata = ChildSecretMetadata<url::Url>;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type ProxyCodeSecret = UserSecret<ProxyCodeSecretKind>;
