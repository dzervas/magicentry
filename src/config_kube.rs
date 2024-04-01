use std::collections::{BTreeMap, HashMap};

use futures::TryStreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::watcher::Event;
use kube::runtime::watcher;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};

use crate::auth_url::AuthUrlScope;
use crate::error::Result;
use crate::CONFIG;

const ANNOTATION_PREFIX: &str = "magicentry.rs/";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IngressConfig {
	pub auth_url: bool,
	pub realms: Vec<String>,
	pub manage_ingress_nginx: bool,
	// TODO: support ingress traefik
	// pub manage_ingress_traefik: bool,
}

impl IngressConfig {
	pub fn from_map(map: &BTreeMap<String, String>) -> Option<Self> {
		let filtered_map = map
			.iter()
			.filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
			.map(|(k, v)| (
				k.replace(ANNOTATION_PREFIX, "").replace("-", "_"),
				v.as_str()
			))
			.collect::<HashMap<String, &str>>();

		Some(Self {
			auth_url: filtered_map.get("auth_url").map(|v| *v == "true").unwrap_or_default(),
			realms: filtered_map.get("realms").map(|v| v.split(",").map(|v| v.to_string()).collect())?,
			manage_ingress_nginx: filtered_map.get("manage_ingress_nginx").map(|v| *v == "true").unwrap_or_default(),
		})
	}

	pub fn to_map(&self) -> BTreeMap<String, String> {
		let mut map = BTreeMap::new();
		map.insert("auth_url".to_string(), self.auth_url.to_string());
		map.insert("realms".to_string(), self.realms.join(",").to_string());
		map.insert("manage_ingress_nginx".to_string(), self.manage_ingress_nginx.to_string());
		map
	}

	pub async fn process(&self, ingress: &Ingress) -> Result<()> {
		let mut config = CONFIG.write().await;
		let no_name = String::new();
		let name = ingress.metadata.name.as_ref().unwrap_or(&no_name);

		if self.auth_url {
			config.auth_url_enable = true;

			let Some(hosts) = ingress.spec.as_ref() else {
				log::warn!("Ingress {:?} has no hosts", name);
				return Ok(());
			};

			for host in hosts.rules.as_ref().unwrap_or(&Vec::new()) {
				let Some(host_str) = host.host.as_ref() else {
					log::warn!("Ingress {:?} has no host", name);
					continue;
				};

				let has_tls = hosts.tls
					.as_ref()
					.is_some_and(|tls|
						tls
						.iter()
						.any(|tls|
							tls.hosts
							.as_ref()
							.unwrap_or(&Vec::new())
							.contains(&host_str)));

				let origin = if has_tls {
					format!("https://{}", host_str)
				} else {
					format!("http://{}", host_str)
				};

				log::info!("Adding auth_url scope for host {:?}", &origin);

				config.auth_url_scopes.push(AuthUrlScope {
					realms: self.realms.clone(),
					origin,
				});
			}
		}

		drop(config);

		Ok(())
	}
}

pub async fn watch() -> Result<()> {
	let client = Client::try_default().await?;
	let ingresses: Api<Ingress> = Api::all(client);

	log::info!("Watching for Ingresses");

	loop {
		watcher::watcher(ingresses.clone(), Default::default())
			.try_for_each(|event| async move {
				// TODO: Take care of deleted events too
				let Event::Applied(ingress) = event else {
					return Ok(());
				};

				let Some(annotations) = ingress.metadata.annotations.as_ref() else {
					return Ok(());
				};

				if !annotations.iter().any(|(k, _)| k.starts_with(ANNOTATION_PREFIX)) {
					return Ok(());
				}

				let name = ingress.metadata.name.clone().unwrap_or_default();

				let Some(ingress_config) = IngressConfig::from_map(annotations) else {
					log::warn!("Ingress {} has invalid magicentry.rs annotations", name);
					return Ok(());
				};

				log::info!("Saw ingress modification {}", name);
				ingress_config.process(&ingress).await.unwrap_or_else(|e| {
					log::error!("Failed to process ingress {}: {:?}", name, e);
				});

				Ok(())
			}
		)
		.await
		.unwrap_or_else(|e| {
			log::error!("Ingress watch stream ended unexpectedly: {:?}", e);
		});

		log::warn!("Ingress watch stream ended unexpectedly - waiting 5 seconds before retrying");
		tokio::time::sleep(std::time::Duration::from_secs(5)).await;
	}
}
