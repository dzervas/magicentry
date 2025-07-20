//! This module contains the kuebernetes-specific functionality of magicentry,
//! which is feature-gated behind the `kube` feature.
//!
//! It provides the necessary structures and functions to manage Kubernetes Ingress
//! resources and their associated services.
//!
//! The main entrypoint is the [watch] function, which is ran alongside the main
//! actix-web server and updates the global config file in the background.

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

/// The prefix for all magicentry-related annotations
const ANNOTATION_PREFIX: &str = "magicentry.rs/";

/// This struct holds the magicentry-specific configuration of a kubernetes
/// Ingress object, based on its annotations
///
/// E.g. `name` is read from the `magicentry.rs/name` annotation
///
/// It essentially adds a new [Service] to the [ConfigFile](crate::ConfigFile)
/// with automatically derived URL, auth-url settings, etc.
///
/// Ingress-specific values (e.g. [manage_ingress_nginx](IngressConfig::manage_ingress_nginx))
/// allows for some implementation-specific behavior
///
/// TODO: There should be a way to track kube-generated services to be able to
/// delete them and avoid updating services defined by the config file
// TODO: Can we use serde instead of the manual from/to btreemap?
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressConfig {
	pub enable: bool,
	pub name: String,
	pub auth_url: bool,
	pub realms: Vec<String>,
	pub manage_ingress_nginx: bool,
	// TODO: support ingress traefik
	// pub manage_ingress_traefik: bool,
}

impl IngressConfig {
	/// Takes an ingress reference and creates a new [Service] object
	/// based on the ingress spec and adds it to the global [static@CONFIG]
	///
	/// Due to the global static mutex, the main actix-web code should pick
	/// up the changes automatically but it might block config reads
	/// for the duration of the write - should be extremely fast
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
			// TODO: Support OIDC & SAML config
			oidc: None,
			saml: None,
		};

		// Take the write lock at the last possible moment and drop it
		// as soon as possible to avoid blocking other threads/contexts
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
}

impl From<&BTreeMap<String, String>> for IngressConfig {
	fn from(value: &BTreeMap<String, String>) -> Self {
		let filtered_map = value
			.iter()
			.filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
			.map(|(k, v)| {
				(
					k.replace(ANNOTATION_PREFIX, "").replace("-", "_"),
					v.as_str(),
				)
			})
			.collect::<HashMap<String, &str>>();

		Self {
			enable: filtered_map
				.get("enable")
				.map(|v| *v == "true")
				.unwrap_or_default(),
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
				.map(|v| v.split(",").map(|v| v.to_string()).collect())
				.unwrap_or_default(),
			manage_ingress_nginx: filtered_map
				.get("manage_ingress_nginx")
				.map(|v| *v == "true")
				.unwrap_or_default(),
		}
	}
}

impl From<&Ingress> for IngressConfig {
	fn from(ingress: &Ingress) -> Self {
		let map: &BTreeMap<String, String> = &ingress.metadata.annotations
			.as_ref()
			.unwrap_or(&BTreeMap::new())
			.iter()
			.filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
			.map(|(k, v)| (k.clone(), v.clone()))
			.collect();

		map.into()
	}
}

/// Takes an ingress resource, tries to cast it to an IngressConfig
/// and then process it with the [IngressConfig::process] method
async fn process_ingress(ingress: &Ingress) {
	let name = ingress.metadata.name.clone().unwrap_or_default();
	log::debug!("Inspecting ingress resource {}", name);

	let ingress_config: IngressConfig = ingress.into();
	if !ingress_config.enable || ingress_config.name.is_empty() {
		log::debug!("Ingress {} is disabled", name);
		return;
	}

	log::info!("Discovered ingress {}", name);
	ingress_config.process(&ingress).await.unwrap_or_else(|e| {
		log::error!("Failed to process ingress {}: {:?}", name, e);
	});
}

/// A kubernetes resource watcher, aimed to watch for ingress resources
/// and update the global config accordingly
///
/// This function is asynchronously ran alongside the main actix-web server
/// and will update the config file in the background
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
