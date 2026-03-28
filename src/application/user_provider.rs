use crate::domain::User;

#[async_trait::async_trait]
pub trait UserProvider: Send + Sync {
	async fn get(&self, email: &str) -> anyhow::Result<Option<User>>;
	async fn add(&mut self, user: User) -> anyhow::Result<()>;
	async fn remove(&mut self, email: &str) -> anyhow::Result<()>;
	async fn update(&mut self, email: &str, user: User) -> anyhow::Result<()>;
}
