use std::sync::Arc;

use crate::domain::Config;

#[async_trait::async_trait]
pub trait ConfigProvider: Send + Sync {
	async fn get(&self) -> anyhow::Result<Arc<Config>>;
	async fn save(&self, config: Config) -> anyhow::Result<()>;
	async fn reload(&self) -> anyhow::Result<()>;
}
