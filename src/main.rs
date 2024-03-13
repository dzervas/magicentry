use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use actix_web::http::header::ContentType;
use actix_web::{get, post, web, App, HttpRequest, HttpResponse};
use actix_web::cookie::{Key, SameSite};
use config::ConfigFile;
use lettre::AsyncTransport;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use lazy_static::lazy_static;
use formatx::formatx;
use log::{info, warn};

#[cfg(not(test))]
use lettre::transport::smtp;

use std::borrow::Cow;

pub mod config;
pub mod error;
pub mod oidc;
pub mod user;

use user::{User, UserLink, UserSession};

pub(crate) const RANDOM_STRING_LEN: usize = 32;

#[cfg(not(test))]
lazy_static! {
	static ref CONFIG_FILE: String = std::env::var("CONFIG_FILE").unwrap_or("config.yaml".to_string());
}

#[cfg(test)]
lazy_static! {
	static ref CONFIG_FILE: String = "config.sample.yaml".to_string();
}

lazy_static! {
	static ref CONFIG: ConfigFile = serde_yaml::from_str::<ConfigFile>(
		&std::fs::read_to_string(CONFIG_FILE.as_str())
			.expect(format!("Unable to open config file `{:?}`", CONFIG_FILE.as_str()).as_str())
		)
		.expect(format!("Unable to parse config file `{:?}`", CONFIG_FILE.as_str()).as_str());
	static ref LOGIN_PAGE_HTML: String = std::fs::read_to_string(format!("{}/login.html", &CONFIG.static_path)).expect(format!("Unable to open login page `{:?}/login.html`", &CONFIG.static_path).as_str());
}

type Response = std::result::Result<HttpResponse, crate::error::Error>;

#[get("/")]
async fn index(session: Session, db: web::Data<SqlitePool>) -> Response {
	let user = if let Some(user) = User::from_session(&db, session).await? {
		user
	} else {
		return Ok(HttpResponse::Found()
			.append_header(("Location", "/login"))
			.finish())
	};

	let alias = if let Some(alias) = user.username.clone() {
		alias
	} else {
		user.email.clone()
	};

	Ok(HttpResponse::Ok()
		// TODO: Add realm
		.append_header((CONFIG.auth_url_user_header.as_str(), alias.clone()))
		.append_header((CONFIG.auth_url_email_header.as_str(), user.email.clone()))
		.append_header((CONFIG.auth_url_name_header.as_str(), user.name.unwrap_or_default()))
		// .append_header((CONFIG.auth_url_realm_header.as_str(), user.realms.join(", ")))
		.body(alias))
}

#[get("/login")]
async fn login_get() -> Response {
	// TODO: Add realm
	let login_page = formatx!(
		LOGIN_PAGE_HTML.as_str(),
		title = &CONFIG.title,
		realm = "default",
		path_prefix = &CONFIG.path_prefix
	)?;

	Ok(HttpResponse::Ok()
		.content_type(ContentType::html())
		.body(login_page))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct LoginInfo {
	email: String,
}

#[cfg(not(test))]
type SmtpTransport = smtp::AsyncSmtpTransport<lettre::Tokio1Executor>;

#[cfg(test)]
type SmtpTransport = lettre::transport::stub::AsyncStubTransport;

#[post("/login")]
async fn login_post(req: HttpRequest, form: web::Form<LoginInfo>, db: web::Data<SqlitePool>, mailer: web::Data<Option<SmtpTransport>>, http_client: web::Data<Option<reqwest::Client>>) -> Response {
	let user = if let Some(user) = User::from_config(&form.email) {
		user
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let link = UserLink::new(&db, user.email.clone()).await?;
	let base_url = CONFIG.url_from_request(&req);
	let magic_link = format!("{}/login/{}", base_url, link.magic);
	let name = &user.name.unwrap_or_default();
	let username = &user.username.unwrap_or_default();

	#[cfg(debug_assertions)]
	println!("Link: {} {:?}", &magic_link, link);

	if let Some(mailer) = mailer.as_ref() {
		let email = lettre::Message::builder()
			.from(CONFIG.smtp_from.parse()?)
			.to(user.email.parse()?)
			.subject(formatx!(&CONFIG.smtp_subject, title = &CONFIG.title)?)
			.body(formatx!(
				&CONFIG.smtp_body,
				link = &magic_link,
				name = name,
				username = username
			)?)?;

		info!("Sending email to {}", &user.email);
		mailer.send(email).await?;
	}

	if let Some(client) = http_client.as_ref() {
		let method = reqwest::Method::from_bytes(CONFIG.request_method.as_bytes()).unwrap();
		let url = formatx!(
			&CONFIG.request_url,
			title = &CONFIG.title,
			link = &magic_link,
			email = &link.email,
			name = name,
			username = username
		)?;
		let mut req = client.request(method, url);

		if let Some(data) = &CONFIG.request_data {
			let body = formatx!(
				data.as_str(),
				title = &CONFIG.title,
				link = &magic_link,
				email = &link.email,
				name = name,
				username = username
			)?;
			req = req.body(body);
		}

		info!("Sending request for user {}", &user.email);
		req.send().await?;
	}

	Ok(HttpResponse::Ok().finish())
}

#[get("/login/{magic}")]
async fn login_magic_action(magic: web::Path<String>, session: Session, db: web::Data<SqlitePool>) -> Response {
	let user = if let Some(user) = UserLink::visit(&db, magic.clone()).await? {
		user
	} else {
		return Ok(HttpResponse::Unauthorized().finish())
	};

	let user_session = UserSession::new(&db, &user).await?;
	info!("User {} logged in", &user.email);
	// TODO: Move to cookies
	session.insert("session", user_session.session_id).unwrap();

	// This assumes that the cookies persist during the link-clicking dance, could embed the state in the link
	if let Some(oidc_authorize) = session.remove_as::<oidc::data::AuthorizeRequest>("oidc_authorize") {
		println!("Session Authorize Request: {:?}", oidc_authorize);
		let oidc_session = oidc_authorize.unwrap().generate_code(&db, user.email.as_str()).await?;
		// TODO: Use `?` instead of `unwrap`
		let redirect_url = oidc_session.get_redirect_url().unwrap();
		info!("Redirecting to client {}", &oidc_session.request.client_id);
		Ok(HttpResponse::Found()
			.append_header(("Location", redirect_url.as_str()))
			.finish())
	} else {
		Ok(HttpResponse::Found()
			.append_header(("Location", "/"))
			.finish())
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LogoutRequest {
	post_logout_redirect_uri: Option<String>,
}

#[get("/logout")]
async fn logout(req: web::Query<LogoutRequest>, session: Session, db: web::Data<SqlitePool>) -> Response {
	if let Some(session_id) = session.get::<String>("session").unwrap_or(None) {
		session.remove("session");
		UserSession::delete_id(&db, &session_id).await?;
	}

	// XXX: Open redirect
	let target_url = if let Some(target) = &req.into_inner().post_logout_redirect_uri {
		urlencoding::decode(&target.clone()).unwrap_or_else(|_| {
			warn!("Invalid logout redirect URL: {}", &target);
			Cow::from("/login")
		}).to_string()
	} else {
		"/login".to_string()
	};

	Ok(HttpResponse::Found()
		.append_header(("Location", target_url.as_str()))
		.finish())
}

// Do not compile in tests at all as the SmtpTransport is not available
#[cfg(not(test))]
#[actix_web::main]
async fn main() -> std::io::Result<()> {
	use actix_web::HttpServer;
	use actix_web::middleware::Logger;

	env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

	#[cfg(debug_assertions)]
	log::warn!("Running in debug mode, all magic links will be printed to the console.");

	// Database setup
	let db = SqlitePool::connect(&CONFIG.database_url).await.expect("Failed to create sqlite pool.");
	let secret = if let Some(secret) = config::ConfigKV::get(&db, "secret").await {
		let master = hex::decode(secret).expect("Failed to decode secret - is something wrong with the database?");
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		config::ConfigKV::set(&db, "secret", &master).await.unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		key
	};

	// Mailer setup
	let mailer: Option<SmtpTransport> = if CONFIG.smtp_enable {
		Some(smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(&CONFIG.smtp_url)
			.expect("Failed to create mailer - is the `smtp_url` correct?")
			.pool_config(smtp::PoolConfig::new())
			.build())
	} else {
		None
	};

	// HTTP client setup
	let http_client = if CONFIG.request_enable {
		Some(reqwest::Client::new())
	} else {
		None
	};

	// OIDC setup
	let oidc_key = oidc::init(&db).await;

	HttpServer::new(move || {
		let app = App::new()
			// Data
			.app_data(web::Data::new(db.clone()))
			.app_data(web::Data::new(mailer.clone()))
			.app_data(web::Data::new(http_client.clone()))

			// Auth routes
			.service(index)
			.service(login_get)
			.service(login_post)
			.service(login_magic_action)
			.service(logout)

			// Middleware
			.wrap(Logger::default())
			.wrap(
				SessionMiddleware::builder(
					CookieSessionStore::default(),
					secret.clone()
				)
				.cookie_same_site(SameSite::Strict)
				.cookie_path(CONFIG.path_prefix.clone())
				.session_lifecycle(
					actix_session::config::PersistentSession::default()
						.session_ttl(actix_web::cookie::time::Duration::try_from(CONFIG.session_duration.to_std().expect("Couldn't parse session_duration")).unwrap())
				)
				.build());

		// OIDC routes
		if CONFIG.oidc_enable {
			app.app_data(web::Data::new(oidc_key.clone()))
				.service(oidc::configuration)
				.service(oidc::authorize_get)
				.service(oidc::authorize_post)
				.service(oidc::token)
				.service(oidc::jwks)
				.service(oidc::userinfo)
		} else {
			app
		}
	})
	.bind(format!("{}:{}", CONFIG.listen_host, CONFIG.listen_port))?
	.run()
	.await
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;

	use super::*;

	use actix_web::cookie::Cookie;
	use actix_web::http::StatusCode;
	use actix_web::test as actix_test;
	use chrono::Utc;
	use sqlx::query;

	pub async fn db_connect() -> SqlitePool {
		SqlitePool::connect(&CONFIG.database_url).await.expect("Failed to create pool.")
	}

	pub fn get_valid_user() -> User {
		let user_email = "valid@example.com";
		let user_realms = vec!["example".to_string()];
		let user = CONFIG
			.users
			.iter()
			.find_map(|u| if u.email == user_email { Some(u.clone()) } else { None })
			.unwrap();

		assert_eq!(user.email, user_email);
		assert_eq!(user.realms, user_realms);

		user
	}

	#[actix_web::test]
	async fn test_login_get() {
		let mut app = actix_test::init_service(App::new().service(login_get)).await;

		let req = actix_test::TestRequest::get()
			.uri("/login")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		// assert_eq!(resp.headers().get("Content-Type").unwrap(), "text/html; charset=utf-8");
	}

	#[actix_web::test]
	async fn test_login_post() {
		let db = &db_connect().await;
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.app_data(web::Data::new(None::<SmtpTransport>))
				.app_data(web::Data::new(None::<reqwest::Client>))
				.service(login_post)
		)
		.await;

		// Login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo { email: "valid@example.com".to_string() })
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);

		// Invalid login
		let req = actix_test::TestRequest::post()
			.uri("/login")
			.set_form(&LoginInfo { email: "invalid@example.com".to_string() })
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
	}

	#[actix_web::test]
	async fn test_login_magic_action() {
		let db = &db_connect().await;
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(login_magic_action)
		)
		.await;

		let expiry = Utc::now().naive_utc() + chrono::Duration::try_days(1).unwrap();
		query!("INSERT INTO links (magic, email, expires_at) VALUES (?, ?, ?) ON CONFLICT(magic) DO UPDATE SET expires_at = ?",
				"valid_magic_link",
				"valid@example.com",
				expiry,
				expiry,
			)
			.execute(db)
			.await
			.unwrap();

		// Assuming a valid session exists in the database
		let req = actix_test::TestRequest::get()
			.uri("/login/valid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);

		// Assuming an invalid session
		let req = actix_test::TestRequest::get()
			.uri("/login/invalid_magic_link")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
	}

	#[actix_web::test]
	async fn test_index() {
		let db = &db_connect().await;
		let mut session_map = HashMap::new();
		let secret = Key::from(&[0; 64]);
		session_map.insert("session".to_string(), "valid_session_id".to_string());

		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.service(login_magic_action)
				.wrap(
					SessionMiddleware::builder(
						CookieSessionStore::default(),
						secret
					)
					.cookie_secure(false)
					.cookie_same_site(SameSite::Strict)
					.build())
		)
		.await;

		let req = actix_test::TestRequest::get().uri("/").to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");

		let expiry = Utc::now().naive_utc() + chrono::Duration::try_days(1).unwrap();
		query!("INSERT INTO links (magic, email, expires_at) VALUES (?, ?, ?) ON CONFLICT(magic) DO UPDATE SET expires_at = ?",
				"valid_magic_link",
				"valid@example.com",
				expiry,
				expiry,
			)
			.execute(db)
			.await
			.unwrap();

		let req = actix_test::TestRequest::get().uri("/login/valid_magic_link").to_request();
		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/");

		let headers = resp.headers().clone();
		let cookie_header = headers.get("set-cookie").unwrap().to_str().unwrap();
		let parsed_cookie = Cookie::parse_encoded(cookie_header).unwrap();

		// TODO: Use actix-session, not plain cookie
		let req = actix_test::TestRequest::get()
			.uri("/")
			.cookie(parsed_cookie)
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::OK);
		assert_eq!(resp.headers().get(CONFIG.auth_url_user_header.as_str()).unwrap(), "valid");
		assert_eq!(resp.headers().get(CONFIG.auth_url_email_header.as_str()).unwrap(), "valid@example.com");

		let req = actix_test::TestRequest::get()
			.uri("/")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::FOUND);
		assert_eq!(resp.headers().get("Location").unwrap(), "/login");
	}
}
