use super::browser_session::BrowserSessionSecretKind;
use super::secret::{EmptyMetadata, UserSecret, UserSecretKind, UserSecretKindEphemeral};

#[derive(PartialEq)]
pub struct LinkLoginSecretKind;

impl UserSecretKind for LinkLoginSecretKind {
	const PREFIX: &'static str = "login";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.link_duration }
}

impl UserSecretKindEphemeral for LinkLoginSecretKind {
	type ExchangeTo = BrowserSessionSecretKind;
}

pub type LinkLoginSecret = UserSecret<LinkLoginSecretKind, EmptyMetadata>;
