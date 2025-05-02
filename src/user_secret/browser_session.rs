use super::secret::{EmptyMetadata, UserSecret, UserSecretKind};

#[derive(PartialEq)]
pub struct BrowserSessionSecretKind;

impl UserSecretKind for BrowserSessionSecretKind {
	const PREFIX: &'static str = "browser_session";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type BrowserSessionSecret = UserSecret<BrowserSessionSecretKind, EmptyMetadata>;
