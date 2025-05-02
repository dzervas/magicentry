use super::secret::{EmptyMetadata, UserSecretKind};

#[derive(PartialEq)]
pub struct LoginSecretKind {}

impl UserSecretKind for LoginSecretKind {
	const PREFIX: &'static str = "login";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.link_duration }
}
