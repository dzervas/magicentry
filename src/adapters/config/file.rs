use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::info;

use crate::application::ConfigProvider;
use crate::domain::Config;

pub struct FileConfigProvider {
	config: ArcSwap<Config>,
	path: PathBuf,
}

impl FileConfigProvider {
	pub fn new(config: Config, path: impl Into<PathBuf>) -> Self {
		Self {
			config: ArcSwap::new(Arc::new(config)),
			path: path.into(),
		}
	}
}

#[async_trait::async_trait]
impl ConfigProvider for FileConfigProvider {
	async fn get(&self) -> anyhow::Result<Arc<Config>> {
		Ok(self.config.load().clone())
	}

	async fn save(&self, _config: Config) -> anyhow::Result<()> {
		anyhow::bail!("Saving the config to a file is not supported!");
	}

	async fn reload(&self) -> anyhow::Result<()> {
		info!("Reloading config from {:?}", self.path);

		let new_config =
			serde_yaml::from_str::<Config>(&std::fs::read_to_string(self.path.clone())?)?;
		self.config.store(Arc::new(new_config));
		Ok(())
	}
}
