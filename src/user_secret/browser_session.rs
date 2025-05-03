use serde::{Deserialize, Serialize};

use super::secret::{UserSecret, UserSecretKind};
use super::metadata::EmptyMetadata;

#[derive(PartialEq, Serialize, Deserialize)]
pub struct BrowserSessionSecretKind;

impl UserSecretKind for BrowserSessionSecretKind {
	const PREFIX: &'static str = "session";
	type Metadata = EmptyMetadata;

	async fn duration() -> chrono::Duration { crate::CONFIG.read().await.session_duration }
}

pub type BrowserSessionSecret = UserSecret<BrowserSessionSecretKind>;
