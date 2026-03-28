use serde::{Deserialize, Serialize};

use crate::{application::UserProvider, domain::User};

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FileUserProvider {
	#[serde(flatten)]
	users: Vec<User>,
}

impl FileUserProvider {
	pub fn new(users: Vec<User>) -> Self {
		Self { users }
	}
}

#[async_trait::async_trait]
impl UserProvider for FileUserProvider {
	async fn get(&self, email: &str) -> anyhow::Result<Option<User>> {
		Ok(self.users.iter().cloned().find(|user| user.email == email))
	}

	async fn add(&mut self, user: User) -> anyhow::Result<()> {
		self.users.push(user);
		Ok(())
	}

	async fn remove(&mut self, email: &str) -> anyhow::Result<()> {
		self.users.retain(|user| user.email != email);
		Ok(())
	}

	async fn update(&mut self, email: &str, user: User) -> anyhow::Result<()> {
		self.users
			.iter_mut()
			.map(|u| {
				if u.email == email {
					*u = user.clone();
				}
			})
			.count();

		Ok(())
	}
}
