use std::collections::{BTreeMap, HashMap};

use actix_web::dev::ServerHandle;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::networking::v1::Ingress;
use kube::api::WatchEvent;
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

		Ok(())
	}
}

pub async fn watch(handle: ServerHandle) -> Result<()> {
	let client = Client::try_default().await?;
	let ingresses: Api<Ingress> = Api::all(client);

	log::info!("Watching for Ingresses");

	// watcher(ingresses, watcher::Config::default())
	// .applied_objects()
	// .try_for_each(|r| async move {
	// 	if skip_initial {
	// 		skip_initial = false;
	// 		return Ok(());
	// 	}

	// 	println!("Ingress Updated: {:?}", r);
	// 	Ok(())
	// }).await?;

	// let wp = WatchParams::default();
	let mut stream = ingresses.watch(&Default::default(), "0").await?.boxed();
	while let Some(status) = stream.try_next().await? {
		let ingress = match status {
			WatchEvent::Added(i) | WatchEvent::Modified(i) | WatchEvent::Deleted(i) => i,
			_ => continue,
		};

		let Some(annotations) = ingress.metadata.annotations.as_ref() else {
			continue;
		};

		if !annotations.iter().any(|(k, _)| k.starts_with(ANNOTATION_PREFIX)) {
			continue;
		}

		let Some(ingress_config) = IngressConfig::from_map(annotations) else {
			log::warn!("Ingress {:?} has invalid magicentry.rs annotations", ingress.metadata.name.as_ref().unwrap());
			continue;
		};

		// if let WatchEvent::Added(_) = status {
		// 	let config = CONFIG.read().await;
		// 	if config.auth_url_scopes.iter().any(|s| s.origin == ingress_config.) {
		// 		// We already know about this ingress
		// 		return Ok(());
		// 	}
		// }

		log::info!("Saw ingress modification {:?}", ingress.metadata.name.as_ref().unwrap());
	}

	Ok(())
}

pub async fn get_current() -> Result<()> {
	let client = Client::try_default().await?;
	let ingresses: Api<Ingress> = Api::all(client);

	let ingress_list = ingresses.list(&Default::default()).await?;
	let ingresses = ingress_list
		.iter()
		.filter(|ingress| ingress.metadata.annotations.is_some())
		.filter(|ingress|
			ingress.metadata.annotations
				.as_ref()
				.unwrap()
				.iter()
				.any(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
		)
		.collect::<Vec<&Ingress>>();

	let mut config = CONFIG.write().await;
	config.title = "Ingresses".to_string();
	println!("Updated title: {}", config.title);
	drop(config);

	for ingress in ingresses {
		let Some(ingress_config) = IngressConfig::from_map(ingress.metadata.annotations.as_ref().unwrap()) else {
			log::warn!("Ingress {:?} has invalid magicentry.rs annotations", ingress.metadata.name.as_ref().unwrap());
			continue;
		};

		ingress_config.process(ingress).await?;
	}

	Ok(())
}
