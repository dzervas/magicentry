use super::browser_session::BrowserSessionSecretKind;
use super::secret::{EphemeralUserSecret, UserSecretKind};
use super::metadata::EmptyMetadata;

pub struct LinkLoginSecretKind;

impl UserSecretKind for LinkLoginSecretKind {
	const PREFIX: &'static str = "login";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.link_duration }
}

pub type LinkLoginSecret = EphemeralUserSecret<LinkLoginSecretKind, BrowserSessionSecretKind>;
