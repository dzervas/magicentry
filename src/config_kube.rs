//! This module contains the kuebernetes-specific functionality of magicentry,
//! which is feature-gated behind the `kube` feature.
//!
//! It provides the necessary structures and functions to manage Kubernetes Ingress
//! resources and their associated services.
//!
//! The main entrypoint is the [watch] function, which is ran alongside the main
//! actix-web server and updates the global config file in the background.

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use futures::TryStreamExt;
use k8s_openapi::api::core::v1::Service as KubeService;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{Api, Client};
use serde::{Deserialize};

use crate::config::Config;
use crate::secret::{SecretString, SecretType};
use crate::service::{Service, ServiceAuthUrl, ServiceOIDC, ServiceSAML};

/// The prefix for all magicentry-related annotations
const ANNOTATION_PREFIX: &str = "magicentry.rs/";

/// This struct holds the magicentry-specific configuration of a kubernetes
/// Ingress object, based on its annotations
///
/// E.g. `name` is read from the `magicentry.rs/name` annotation
///
/// It essentially adds a new [Service] to the [`ConfigFile`](crate::ConfigFile)
/// with automatically derived URL, auth-url settings, etc.
///
/// Ingress-specific values (e.g. [`manage_ingress_nginx`](IngressConfig::manage_ingress_nginx))
/// allows for some implementation-specific behavior
///
// TODO: Create a custom serde deserializer for Service instead of this
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct KubeServiceAnnotations {
	pub name: String,
	pub url: String,
	pub realms: String, // comma-separated list of realms
	pub auth_url_origins: Option<String>, // comma-separated list of origins for the auth-url
	pub auth_url_status_url: Option<String>,

	/// OIDC configuration
	/// `MagicEntry` automatically creates (and maintains) a secret with the OIDC credentials
	/// (data keys are `clientID` and `clientSecret`)
	pub oidc_target_secret: Option<String>,
	pub oidc_redirect_urls: Option<String>,

	/// SAML configuration from within kubernetes
	pub saml_entity_id: Option<String>,
	pub saml_redirect_urls: Option<String>,
}

fn normalized_annotations(
    map: &BTreeMap<String, String>,
) -> serde_json::Value {
    let obj = map.iter()
        .filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
        .map(|(k, v)| {
            (
                k.trim_start_matches(ANNOTATION_PREFIX).to_string(),
                serde_json::Value::String(v.clone()),
            )
        })
        .collect::<serde_json::Map<String, serde_json::Value>>();

    serde_json::Value::Object(obj)
}

impl TryFrom<&KubeService> for KubeServiceAnnotations {
    type Error = anyhow::Error;

    fn try_from(service: &KubeService) -> anyhow::Result<Self> {
	    let default_map = BTreeMap::new();
        let labels = service.metadata.annotations.as_ref().unwrap_or(&default_map);
        let de = normalized_annotations(labels);
        Ok(serde_json::from_value(de)?)
    }
}

pub async fn add_service_from_kube(config: Arc<ArcSwap<Config>>, service: &KubeService) -> anyhow::Result<()> {
	let enabled = service.metadata.labels.as_ref()
		.and_then(|labels| labels.get("magicentry.rs/enable"))
		.is_some_and(|v| v == "true");
	if !enabled {
		tracing::info!("Kubernetes service {:?} is disabled, removing", service.metadata.name.as_ref().unwrap_or(&String::new()));
		return remove_service_from_kube(config, service).await;
	}

	let annotations = KubeServiceAnnotations::try_from(service)?;

	let new_service = Service {
		name: annotations.name.clone(),
		url: url::Url::parse(&annotations.url)?,
		realms: annotations.realms.split(',').map(ToString::to_string).collect(),
		auth_url: annotations.auth_url_origins.and_then(|origins|
			Some(ServiceAuthUrl {
				origins: origins.split(',').map(ToString::to_string).collect(),
				status_url: annotations.auth_url_status_url.and_then(|u| url::Url::parse(&u).ok()),
				status_cookies: None, // TODO: support auth-url cookies from labels too
				status_auth: None, // TODO: support auth-url auth from labels too
				status_headers: None, // TODO: support auth-url headers from labels too
			})
		),

		oidc: annotations.oidc_redirect_urls.and_then(|redirect_urls|
			Some(ServiceOIDC {
				client_id: format!("kube-{}", annotations.name).to_string(),
				client_secret: SecretString::new(&SecretType::KubeOIDCSecret).to_str_that_i_wont_print().to_string(),
				redirect_urls: redirect_urls.split(',').filter_map(|u| url::Url::parse(u).ok()).collect(),
			})
		),
		saml: annotations.saml_redirect_urls.and_then(|redirect_urls|
			Some(ServiceSAML {
				entity_id: annotations.saml_entity_id.clone().unwrap_or_else(|| format!("kube-{}", annotations.name)),
				redirect_urls: redirect_urls.split(',').filter_map(|u| url::Url::parse(u).ok()).collect(),
			})
		),
	};

	let name = &annotations.name;
	let config_ref = config.load();
	let mut new_config: Config = (*config_ref).as_ref().clone();
	if new_config.services.get(name).is_none() {
		tracing::info!("Adding service {name:?} to config");
		new_config.services.0.push(new_service);
	} else if let Some(existing_service) = new_config.services.get_mut(name)
		&& existing_service != &new_service
	{
		tracing::info!("Updating service {name} in config");
		*existing_service = new_service;
	}

	config.store(Arc::new(new_config));

	Ok(())
}

pub async fn remove_service_from_kube(config: Arc<ArcSwap<Config>>, service: &KubeService) -> anyhow::Result<()> {
	let name = KubeServiceAnnotations::try_from(service)?.name;
	let config_ref = config.load();
	let mut new_config: Config = (*config_ref).as_ref().clone();

	if new_config.services.get(&name).is_none() {
		tracing::info!("Skipping removal of service {name:?} since it doesn't exist");
	} else {
		tracing::info!("Removing service {name:?} from the config");
		new_config.services.0.retain(|s| s.name != name);
		config.store(Arc::new(new_config));
	}

	Ok(())
}

pub async fn watch_service(config: Arc<ArcSwap<Config>>, service: Api<KubeService>) -> anyhow::Result<()>
{
	tracing::info!("Watching for kubernetes service resources");
	let watcher_config = watcher::Config {
		label_selector: Some(format!("{ANNOTATION_PREFIX}enable=true")),
		..Default::default()
	};

	loop {
		watcher::watcher(service.clone(), watcher_config.clone())
			.try_for_each(|event| {
				let config = config.clone();
				async move {
					match event {
						Event::Apply(svc) | Event::InitApply(svc) => {
							tracing::info!("Kubernetes service resource {:?} was created/updated", svc.metadata.name.clone().unwrap_or_default());
							add_service_from_kube(config, &svc).await.unwrap_or_else(|e| {
								tracing::error!("Failed to process kubernetes service resource {:?}: {e:?}", svc.metadata.name.unwrap_or_default());
							});
						},
						Event::Delete(svc) => {
							// TODO: Take care of deleted events too
							tracing::info!("Kubernetes service resource {:?} was deleted", svc.metadata.name.clone().unwrap_or_default());
							remove_service_from_kube(config, &svc).await.unwrap_or_else(|e| {
								tracing::error!("Failed to process deletion of kubernetes service resource {:?}: {e:?}", svc.metadata.name.unwrap_or_default());
							});
						}
						_ => {}
					}

					Ok(())
				}
			}
		)
		.await
		.unwrap_or_else(|e| {
			tracing::error!("Service watch stream ended unexpectedly: {e:?}");
		});

		tracing::warn!(
			"Service watch stream ended unexpectedly - waiting 5 seconds before retrying"
		);
		tokio::time::sleep(std::time::Duration::from_secs(5)).await;
	}
}

/// A kubernetes resource watcher, aimed to watch for ingress resources
/// and update the global config accordingly
///
/// This function is asynchronously ran alongside the main actix-web server
/// and will update the config file in the background
pub async fn watch(config: Arc<ArcSwap<Config>>) -> anyhow::Result<()> {
	let client = Client::try_default()
		.await
		.context("Could not open the default kubernetes client for watching")?;
	let services: Api<KubeService> = Api::all(client.clone());

	watch_service(config, services).await
}
