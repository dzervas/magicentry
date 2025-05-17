use std::collections::{BTreeMap, HashMap};

use futures::TryStreamExt;
use k8s_openapi::api::networking::v1::Ingress;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{Api, Client};
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::service::{Service, ServiceAuthUrl};
use crate::CONFIG;

const ANNOTATION_PREFIX: &str = "magicentry.rs/";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IngressConfig {
	pub name: String,
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
			.map(|(k, v)| {
				(
					k.replace(ANNOTATION_PREFIX, "").replace("-", "_"),
					v.as_str(),
				)
			})
			.collect::<HashMap<String, &str>>();

		// TODO: Use the whole service struct
		Some(Self {
			name: filtered_map
				.get("name")
				.map(|v| v.to_string())
				.unwrap_or_default(),
			auth_url: filtered_map
				.get("auth_url")
				.map(|v| *v == "true")
				.unwrap_or_default(),
			realms: filtered_map
				.get("realms")
				.map(|v| v.split(",").map(|v| v.to_string()).collect())?,
			manage_ingress_nginx: filtered_map
				.get("manage_ingress_nginx")
				.map(|v| *v == "true")
				.unwrap_or_default(),
		})
	}

	pub fn to_map(&self) -> BTreeMap<String, String> {
		let mut map = BTreeMap::new();
		map.insert("name".to_string(), self.name.to_string());
		map.insert("auth_url".to_string(), self.auth_url.to_string());
		map.insert("realms".to_string(), self.realms.join(",").to_string());
		map.insert(
			"manage_ingress_nginx".to_string(),
			self.manage_ingress_nginx.to_string(),
		);
		map
	}

	pub async fn process(&self, ingress: &Ingress) -> Result<()> {
		let no_name = String::new();
		let name = ingress.metadata.name.as_ref().unwrap_or(&no_name);

		let tls = ingress.spec.as_ref().and_then(|spec| spec.tls.as_ref());
		let urls = ingress.spec
			.as_ref()
			.and_then(|spec| spec.rules.as_ref())
			.and_then(|rules| rules.first())
			.and_then(|rule| rule.host.as_ref())
			.map(|host| {
				let has_tls = tls.map_or(false, |tls| {
					tls.iter().any(|tls| {
						tls.hosts
							.as_ref()
							.unwrap_or(&Vec::new())
							.contains(host)
					})
				});

				let mut url = url::Url::parse(&host).unwrap_or_else(|_| {
					log::error!("Ingress {:?} has invalid host {}", name, host);
					url::Url::parse("http://localhost").unwrap()
				});
				url.set_scheme(if has_tls { "https" } else { "http" }).unwrap();

				url
			})
			.iter().cloned().collect::<Vec<_>>();
		let Some(service_url) = urls.get(0).cloned() else {
			log::warn!("Ingress {} has no host", name);
			return Err(AppErrorKind::IngressHasNoHost.into());
		};

		let service = Service {
			name: self.name.clone(),
			// Iterate over spec.rules[].host and see if spec.tls[].hosts contains the host
			url: service_url,
			realms: self.realms.clone(),
			auth_url: if self.auth_url {
				Some(ServiceAuthUrl {
					origins: urls
						.iter()
						.map(|url| url.to_string())
						.collect(),
				})
			} else {
				None
			},
			oidc: None,
			saml: None,
		};

		let mut config = CONFIG.write().await;
		if config.services.get(name).is_none() {
			log::info!("Adding service {} to config", name);
			config.services.0.push(service.clone());
		} else if let Some(existing_service) = config.services.get_mut(name) {
			if existing_service != &service {
				log::info!("Updating service {} in config", name);
				*existing_service = service.clone();
			}
		}
		drop(config);

		Ok(())
	}

	pub async fn from_ingress(ingress: &Ingress) -> Option<Self> {
		let annotations = get_ingress_annotations(ingress).await;
		Self::from_map(&annotations)
	}
}

async fn get_ingress_annotations(ingress: &Ingress) -> BTreeMap<String, String> {
	ingress
		.metadata
		.annotations
		.as_ref()
		.unwrap_or(&BTreeMap::new())
		.iter()
		.filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
		.map(|(k, v)| (k.clone(), v.clone()))
		.collect()
}

async fn process_ingress(ingress: &Ingress) {
	let name = ingress.metadata.name.clone().unwrap_or_default();

	log::debug!("Inspecting ingress resource {}", name);
	let Some(ingress_config) = IngressConfig::from_ingress(&ingress).await else {
		return;
	};

	log::info!("Discovered ingress {}", name);
	ingress_config.process(&ingress).await.unwrap_or_else(|e| {
		log::error!("Failed to process ingress {}: {:?}", name, e);
	});
}

pub async fn watch() -> Result<()> {
	let client = Client::try_default().await?;
	let ingresses: Api<Ingress> = Api::all(client);

	log::info!("Watching for Ingresses");

	loop {
		watcher::watcher(ingresses.clone(), Default::default())
			.try_for_each(|event| async move {
				match event {
					Event::Apply(ingress) => process_ingress(&ingress).await,
					Event::InitApply(ingress) => process_ingress(&ingress).await,
					Event::Delete(ingress) => {
						// TODO: Take care of deleted events too
						log::warn!("Ingress {} was deleted but was not removed from the config - this feature is not implemented yet", ingress.metadata.name.clone().unwrap_or_default());
					}
					_ => {}
				}

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
