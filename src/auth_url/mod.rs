use serde::{Deserialize, Serialize};

pub mod handle_response;
pub mod handle_status;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AuthUrlScope {
	pub origin: String,
	pub realms: Vec<String>,
}
