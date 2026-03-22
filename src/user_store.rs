use serde::{Deserialize, Serialize};

use crate::user::User;

pub trait UserStore {
	fn from_email(&self, email: &str) -> Option<User>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigUserStore(Vec<User>);

impl ConfigUserStore {
	pub fn new(users: Vec<User>) -> Self {
		ConfigUserStore(users)
	}
}

impl UserStore for ConfigUserStore {
	fn from_email(&self, email: &str) -> Option<User> {
		self.0.iter().find(|user| user.email == email).cloned()
	}
}
