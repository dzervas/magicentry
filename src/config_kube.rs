//! This module contains the kuebernetes-specific functionality of magicentry,
//! which is feature-gated behind the `kube` feature.
//!
//! It provides the necessary structures and functions to manage Kubernetes Ingress
//! resources and their associated services.
//!
//! The main entrypoint is the [watch] function, which is ran alongside the main
//! actix-web server and updates the global config file in the background.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use anyhow::Context;
use arc_swap::ArcSwap;
use futures::TryStreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{Secret, Service as KubeService};
use k8s_openapi::api::networking::v1::Ingress;
use kube::core::ObjectMeta;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{
	Api, Client,
	api::{Patch, PatchParams},
};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::secret::{SecretString, SecretType};
use crate::CONFIG;
use crate::error::{AppError, AuthError};
use crate::service::{Service, ServiceAuthUrl, ServiceOIDC, ServiceSAML};
use crate::utils::random_string;

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
/// TODO: There should be a way to track kube-generated services to be able to
/// delete them and avoid updating services defined by the config file
// TODO: Can we use serde instead of the manual from/to btreemap?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngressConfig {
	pub enable: bool,
	pub name: String,
	pub realms: Vec<String>,
	pub auth_url: bool,

	/// OIDC configuration
	/// `MagicEntry` automatically creates (and maintains) a secret with the OIDC credentials
	/// (data keys are `clientID` and `clientSecret`)
	pub oidc_target_secret: Option<String>,
	pub oidc_redirect_urls: Vec<url::Url>,

	/// SAML configuration from within kubernetes
	pub saml_entity_id: Option<String>,
	pub saml_redirect_urls: Vec<url::Url>,

	pub manage_ingress_nginx: bool,
	// TODO: support ingress traefik, kong, etc.
	// pub manage_ingress_traefik: bool,
}

impl IngressConfig {
	/// Takes an ingress reference and creates a new [Service] object
	/// based on the ingress spec and adds it to the global [static@CONFIG]
	///
	/// Due to the global static mutex, the main actix-web code should pick
	/// up the changes automatically but it might block config reads
	/// for the duration of the write - should be extremely fast
	// TODO: Refactor this function
	#[allow(clippy::cognitive_complexity)]
	#[allow(clippy::too_many_lines)]
	pub async fn process(&self, ingress: &Ingress) -> Result<(), AppError> {
		let no_name = String::new();
		let name = ingress.metadata.name.as_ref().unwrap_or(&no_name);

		let tls = ingress.spec.as_ref().and_then(|spec| spec.tls.as_ref());
		let urls = ingress
			.spec
			.as_ref()
			.and_then(|spec| spec.rules.as_ref())
			.and_then(|rules| rules.first())
			.and_then(|rule| rule.host.as_ref())
			.map(|host| {
				let has_tls = tls.is_some_and(|tls| {
					tls.iter()
						.any(|tls| tls.hosts.as_ref().unwrap_or(&Vec::new()).contains(host))
				});

				let mut url = url::Url::parse(host).unwrap_or_else(|_| {
					tracing::error!("Ingress {name:?} has invalid host {host}");
					#[allow(clippy::unwrap_used)] // const
					url::Url::parse("http://localhost").unwrap()
				});
				#[allow(clippy::unwrap_used)] // const
				url.set_scheme(if has_tls { "https" } else { "http" })
					.unwrap();

				url
			})
			.iter()
			.cloned()
			.collect::<Vec<_>>();
		let Some(service_url) = urls.first().cloned() else {
			tracing::warn!("Ingress {name} has no host");
			return Err(AuthError::IngressHasNoHost.into());
		};

		let oidc = if let Some(secret_name) = &self.oidc_target_secret {
			let namespace = ingress.metadata.namespace.as_deref().unwrap_or("default");
			let client = Client::try_default()
				.await
				.context("Could not open the default kubernetes client")?;
			let secrets: Api<Secret> = Api::namespaced(client, namespace);

			let existing = secrets
				.get_opt(secret_name)
				.await
				.context("Failed to get the kubernetes secret")?;
			let client_id = existing
				.as_ref()
				.and_then(|s| s.data.as_ref())
				.and_then(|d| d.get("clientID"))
				.and_then(|b| String::from_utf8(b.0.clone()).ok())
				.unwrap_or_else(random_string);
			let client_secret = existing
				.as_ref()
				.and_then(|s| s.data.as_ref())
				.and_then(|d| d.get("clientSecret"))
				.and_then(|b| String::from_utf8(b.0.clone()).ok())
				.unwrap_or_else(random_string);

			let mut data = BTreeMap::new();
			data.insert(
				"clientID".to_string(),
				ByteString(client_id.clone().into_bytes()),
			);
			data.insert(
				"clientSecret".to_string(),
				ByteString(client_secret.clone().into_bytes()),
			);

			let annotations =
				BTreeMap::from([("app.kubernetes.io/part-of".to_string(), self.name.clone())]);

			let secret = Secret {
				metadata: ObjectMeta {
					name: Some(secret_name.clone()),
					annotations: Some(annotations),
					..ObjectMeta::default()
				},
				data: Some(data),
				type_: Some("Opaque".to_string()),
				..Secret::default()
			};

			let pp = PatchParams::apply("magicentry").force();
			let patch = Patch::Apply(&secret);
			secrets
				.patch(secret_name, &pp, &patch)
				.await
				.context("Failed to patch the kubernetes secret")?;

			Some(ServiceOIDC {
				client_id,
				client_secret,
				redirect_urls: self.oidc_redirect_urls.clone(),
			})
		} else {
			None
		};

		let service = Service {
			name: self.name.clone(),
			// Iterate over spec.rules[].host and see if spec.tls[].hosts contains the host
			url: service_url,
			realms: self.realms.clone(),
			auth_url: if self.auth_url {
				Some(ServiceAuthUrl {
					origins: urls.iter().map(ToString::to_string).collect(),
					..ServiceAuthUrl::default()
				})
			} else {
				None
			},
			oidc,
			saml: None,
		};

		// Take the write lock at the last possible moment and drop it
		// as soon as possible to avoid blocking other threads/contexts
		let mut config_ref = CONFIG.write().await;
		let config =
			Arc::get_mut(&mut config_ref).context("Failed to get mutable reference to config")?;
		if config.services.get(name).is_none() {
			tracing::info!("Adding service {name} to config");
			config.services.0.push(service.clone());
		} else if let Some(existing_service) = config.services.get_mut(name)
			&& existing_service != &service
		{
			tracing::info!("Updating service {name} in config");
			*existing_service = service.clone();
		}

		Ok(())
	}
}

impl From<&BTreeMap<String, String>> for IngressConfig {
	#[allow(clippy::single_char_pattern)]
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
			enable: filtered_map.get("enable").is_some_and(|v| *v == "true"),
			name: filtered_map
				.get("name")
				.map(|v| (*v).to_string())
				.unwrap_or_default(),
			auth_url: filtered_map.get("auth_url").is_some_and(|v| *v == "true"),
			realms: filtered_map
				.get("realms")
				.map(|v| v.split(",").map(ToString::to_string).collect())
				.unwrap_or_default(),
			oidc_target_secret: filtered_map
				.get("oidc_target_secret")
				.map(|v| (*v).to_string()),
			oidc_redirect_urls: filtered_map
				.get("oidc_redirect_urls")
				.map(|v| {
					v.split(",")
						.filter_map(|u| url::Url::parse(u).ok())
						.collect()
				})
				.unwrap_or_default(),
			saml_entity_id: filtered_map.get("saml_entity_id").map(|v| (*v).to_string()),
			saml_redirect_urls: filtered_map
				.get("saml_redirect_urls")
				.map(|v| {
					v.split(",")
						.filter_map(|u| url::Url::parse(u).ok())
						.collect()
				})
				.unwrap_or_default(),
			manage_ingress_nginx: filtered_map
				.get("manage_ingress_nginx")
				.is_some_and(|v| *v == "true"),
		}
	}
}

impl From<&Ingress> for IngressConfig {
	fn from(ingress: &Ingress) -> Self {
		let map: &BTreeMap<String, String> = &ingress
			.metadata
			.annotations
			.as_ref()
			.unwrap_or(&BTreeMap::new())
			.iter()
			.filter(|(k, _)| k.starts_with(ANNOTATION_PREFIX))
			.map(|(k, v)| (k.clone(), v.clone()))
			.collect();

		map.into()
	}
}

/// Takes an ingress resource, tries to cast it to an `IngressConfig`
/// and then process it with the [`IngressConfig::process`] method
async fn process_ingress(ingress: &Ingress) {
	let name = ingress.metadata.name.clone().unwrap_or_default();
	tracing::debug!("Inspecting ingress resource {name}");

	let ingress_config: IngressConfig = ingress.into();
	if !ingress_config.enable || ingress_config.name.is_empty() {
		tracing::debug!("Ingress {name} is disabled");
		return;
	}

	tracing::info!("Discovered ingress {name}");
	ingress_config.process(ingress).await.unwrap_or_else(|e| {
		tracing::error!("Failed to process ingress {name}: {e:?}");
	});
}

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
