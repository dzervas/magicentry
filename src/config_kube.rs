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
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::ByteString;
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::{api::{Patch, PatchParams}, Api, Client};
use kube::core::ObjectMeta;
use serde::{Deserialize, Serialize};

use crate::error::{AppErrorKind, Result};
use crate::service::{Service, ServiceAuthUrl, ServiceOIDC};
use crate::utils::random_string;
use crate::CONFIG;

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
				let has_tls = tls.is_some_and(|tls|
					tls.iter().any(|tls| {
						tls.hosts
							.as_ref()
							.unwrap_or(&Vec::new())
							.contains(host)
					})
				);

				let mut url = url::Url::parse(host).unwrap_or_else(|_| {
					tracing::error!("Ingress {name:?} has invalid host {host}");
					#[allow(clippy::unwrap_used)] // const
					url::Url::parse("http://localhost").unwrap()
				});
				#[allow(clippy::unwrap_used)] // const
				url.set_scheme(if has_tls { "https" } else { "http" }).unwrap();

				url
			})
			.iter().cloned().collect::<Vec<_>>();
		let Some(service_url) = urls.first().cloned() else {
			tracing::warn!("Ingress {name} has no host");
			return Err(AppErrorKind::IngressHasNoHost.into());
		};

		let oidc = if let Some(secret_name) = &self.oidc_target_secret {
			let namespace = ingress.metadata.namespace.as_deref().unwrap_or("default");
			let client = Client::try_default().await?;
			let secrets: Api<Secret> = Api::namespaced(client, namespace);

			let existing = secrets.get_opt(secret_name).await?;
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
			data.insert("clientID".to_string(), ByteString(client_id.clone().into_bytes()));
			data.insert("clientSecret".to_string(), ByteString(client_secret.clone().into_bytes()));

			let annotations = BTreeMap::from([("app.kubernetes.io/part-of".to_string(), self.name.clone())]);

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
			secrets.patch(secret_name, &pp, &patch).await?;

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
					origins: urls
						.iter()
						.map(ToString::to_string)
						.collect(),
				})
			} else {
				None
			},
			oidc,
			saml: None,
		};

		// Take the write lock at the last possible moment and drop it
		// as soon as possible to avoid blocking other threads/contexts
		let mut config = CONFIG.write().await;
		if config.services.get(name).is_none() {
			tracing::info!("Adding service {name} to config");
			config.services.0.push(service.clone());
		} else if let Some(existing_service) = config.services.get_mut(name) && existing_service != &service  {
			tracing::info!("Updating service {name} in config");
			*existing_service = service.clone();
		}
		drop(config);

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
			enable: filtered_map
				.get("enable")
				.is_some_and(|v| *v == "true"),
			name: filtered_map
				.get("name")
				.map(|v| (*v).to_string())
				.unwrap_or_default(),
			auth_url: filtered_map
				.get("auth_url")
				.is_some_and(|v| *v == "true"),
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
			saml_entity_id: filtered_map
				.get("saml_entity_id")
				.map(|v| (*v).to_string()),
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

/// A kubernetes resource watcher, aimed to watch for ingress resources
/// and update the global config accordingly
///
/// This function is asynchronously ran alongside the main actix-web server
/// and will update the config file in the background
pub async fn watch() -> Result<()> {
	let client = Client::try_default().await?;
	let ingresses: Api<Ingress> = Api::all(client);

	tracing::info!("Watching for Ingresses");

	loop {
		watcher::watcher(ingresses.clone(), watcher::Config::default())
			.try_for_each(|event| async move {
				match event {
					Event::Apply(ingress) | Event::InitApply(ingress) => process_ingress(&ingress).await,
					Event::Delete(ingress) => {
						// TODO: Take care of deleted events too
						tracing::warn!("Ingress {} was deleted but was not removed from the config - this feature is not implemented yet", ingress.metadata.name.unwrap_or_default());
					}
					_ => {}
				}

				Ok(())
			}
		)
		.await
		.unwrap_or_else(|e| {
			tracing::error!("Ingress watch stream ended unexpectedly: {e:?}");
		});

		tracing::warn!("Ingress watch stream ended unexpectedly - waiting 5 seconds before retrying");
		tokio::time::sleep(std::time::Duration::from_secs(5)).await;
	}
}
