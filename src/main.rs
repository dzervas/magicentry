use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use actix_web::{get, post, web, App, HttpResponse, Responder, Result as AwResult};
#[allow(unused_imports)]
use actix_web::HttpServer;
use actix_web::cookie::{Key, SameSite};
use chrono::Duration;
use config::ConfigFile;
use maud::{html, Markup};
#[allow(unused_imports)]
use lettre::transport::smtp;
use lettre::AsyncTransport;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use lazy_static::lazy_static;
use toml;

use std::env;

pub mod config;
pub mod partials;
pub mod user;

use user::{UserLink, UserSession};

pub(crate) const RANDOM_STRING_LEN: usize = 32;

#[cfg(not(test))]
lazy_static! {
	static ref CONFIG_FILE: String = env::var("CONFIG_FILE").unwrap_or("config.toml".to_string());
}

#[cfg(test)]
lazy_static! {
	static ref CONFIG_FILE: String = "config.sample.toml".to_string();
}

lazy_static! {
	static ref CONFIG: ConfigFile = toml::from_str::<ConfigFile>(
		&std::fs::read_to_string(CONFIG_FILE.as_str())
			.expect(format!("Unable to open config file `{:?}`", CONFIG_FILE.as_str()).as_str())
		)
		.expect(format!("Unable to parse config file `{:?}`", CONFIG_FILE.as_str()).as_str());

	static ref DATABASE_URL: String = env::var("DATABASE_URL").unwrap_or("sqlite://database.sqlite3".to_string());

	static ref LISTEN_HOST: String = env::var("LISTEN_HOST").unwrap_or("127.0.0.1".to_string());
	static ref LISTEN_PORT: String = env::var("LISTEN_PORT").unwrap_or("8080".to_string());

	static ref LINK_DURATION: Duration = duration_str::parse_chrono(env::var("LINK_DURATION").unwrap_or("12h".to_string())).unwrap();
	static ref SESSION_DURATION: Duration = duration_str::parse_chrono(env::var("SESSION_DURATION").unwrap_or("1mon".to_string())).unwrap();

	static ref AUTHORIZATION_ALIAS_HEADER: String = env::var("AUTHORIZATION_ALIAS_HEADER").unwrap_or("X-Authenticated-User".to_string());
	static ref AUTHORIZATION_EMAIL_HEADER: String = env::var("AUTHORIZATION_EMAIL_HEADER").unwrap_or("X-Authenticated-Email".to_string());

	static ref SMTP_URL: Option<String> = env::var_os("SMTP_URL").map(|s| s.into_string().unwrap());
	static ref SMTP_FROM: String = env::var("SMTP_FROM").unwrap_or("Just Passwordless <just-passwordless@example.com>".to_string());

	static ref TITLE: String = env::var("TITLE").unwrap_or("Login".to_string());
}

#[get("/")]
async fn index(session: Session, db: web::Data<SqlitePool>) -> impl Responder {
	let session_id = if let Some(session) = session.get::<String>("session").unwrap_or(None) {
		session
	} else {
		return HttpResponse::Unauthorized().finish()
	};


	let session = if let Some(session) = UserSession::from_id(&db, &session_id).await {
		session
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	let user = if let Some(user) = CONFIG.users.iter().find_map(|u| if u.email == session.email { Some(u) } else { None }) {
		user
	} else {
		session.delete(&db).await.unwrap();
		return HttpResponse::Unauthorized().finish()
	};

	let alias = if let Some(alias) = user.alias.clone() {
		alias
	} else {
		user.email.clone()
	};

	HttpResponse::Ok()
		.append_header((AUTHORIZATION_ALIAS_HEADER.as_str(), alias.clone()))
		.append_header((AUTHORIZATION_EMAIL_HEADER.as_str(), user.email.clone()))
		.body(alias)
}

#[get("/login")]
async fn login_get() -> AwResult<Markup> {
	Ok(html! {
		head {
			(partials::header(TITLE.as_str()));
		}
		body {
			(partials::login_form());
			// (partials::footer());
		}
	})

}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct LoginInfo {
	email: String,
}

#[cfg(not(test))]
type SmtpTrasport = smtp::AsyncSmtpTransport<lettre::Tokio1Executor>;

#[cfg(test)]
type SmtpTrasport = lettre::transport::stub::AsyncStubTransport;

#[post("/login")]
async fn login_post(form: web::Form<LoginInfo>, db: web::Data<SqlitePool>, mailer: web::Data<Option<SmtpTrasport>>) -> impl Responder {
	let user = if let Some(user) = CONFIG.users.iter().find_map(|u| if u.email == form.email { Some(u) } else { None }) {
		user
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	let link = UserLink::new(&db, user.email.clone()).await;
	println!("Link: http://{}:{}/login/{} {:?}", crate::LISTEN_HOST.as_str(), crate::LISTEN_PORT.as_str(), link.magic, link);

	if let Some(mailer) = mailer.as_ref() {
		let email = lettre::Message::builder()
			.from(SMTP_FROM.as_str().parse().unwrap())
			.to(user.email.parse().unwrap())
			.subject("Login to realm")
			.body(format!("Click the link to login: http://{}:{}/login/{}", crate::LISTEN_HOST.as_str(), crate::LISTEN_PORT.as_str(), link.magic))
			.unwrap();

		mailer.send(email).await.unwrap();
	}

	// let session_link = format!("/login/{}", session_id);
	// send_email(&info.email, &session_link);

	HttpResponse::Ok().finish()
}

#[get("/login/{magic}")]
async fn login_magic_action(magic: web::Path<String>, session: Session, db: web::Data<SqlitePool>) -> impl Responder {
	let user = if let Some(user) = UserLink::visit(&db, magic.clone()).await {
		user
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	let user_session = if let Ok(user_session) = UserSession::new(&db, &user).await {
		user_session
	} else {
		return HttpResponse::InternalServerError().finish()
	};
	session.insert("session", user_session.session_id).unwrap();

	HttpResponse::Found().append_header(("Location", "/")).finish()
}

#[get("/logout")]
async fn logout(session: Session, db: web::Data<SqlitePool>) -> impl Responder {
	let session_id = if let Some(session) = session.get::<String>("session").unwrap_or(None) {
		session
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	if UserSession::delete_id(&db, &session_id).await.is_ok() {
		session.remove("session");
		HttpResponse::Found().append_header(("Location", "/login")).finish()
	} else {
		HttpResponse::InternalServerError().finish()
	}
}

#[cfg(not(test))] // Do not compile in tests at all as the SmtpTransport is not available
#[actix_web::main]
async fn main() -> std::io::Result<()> {
	// Database setup
	let db = SqlitePool::connect(&DATABASE_URL).await.expect("Failed to create pool.");
	let secret = if let Some(secret) = config::ConfigKV::get(&db, "secret").await {
		let master = hex::decode(secret).unwrap();
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		config::ConfigKV::set(&db, "secret", &master).await.unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		key
	};

	// Mailer setup
	let mailer: Option<SmtpTrasport> = if let Some(smtp_url) = SMTP_URL.as_ref() {
		Some(smtp::AsyncSmtpTransport::<lettre::Tokio1Executor>::from_url(smtp_url)
			.unwrap()
			.pool_config(smtp::PoolConfig::new())
			.build())
	} else {
		None
	};

	HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(db.clone()))
			.app_data(web::Data::new(mailer.clone()))
			.service(index)
			.service(login_get)
			.service(login_post)
			.service(login_magic_action)
			.service(logout)
			.wrap(
				SessionMiddleware::builder(
					CookieSessionStore::default(),
					secret.clone()
				)
				.cookie_same_site(SameSite::Strict)
				.build())
	})
	.bind(format!("{}:{}", LISTEN_HOST.as_str(), LISTEN_PORT.as_str()))?
	.run()
	.await
}

#[cfg(test)]
mod tests {
	use super::*;

	use actix_web::cookie::Cookie;
	use actix_web::http::StatusCode;
	use actix_web::test as actix_test;
	use chrono::Utc;
	use sqlx::query;

	pub async fn db_connect() -> SqlitePool {
		SqlitePool::connect(&DATABASE_URL).await.expect("Failed to create pool.")
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
				.app_data(web::Data::new(None::<SmtpTrasport>))
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
		let secret = Key::generate();
		let mut app = actix_test::init_service(
			App::new()
				.app_data(web::Data::new(db.clone()))
				.service(index)
				.wrap(
					SessionMiddleware::builder(
						CookieSessionStore::default(),
						secret
					)
					.cookie_same_site(SameSite::Strict)
					.build())
		)
		.await;

		let expiry = Utc::now().naive_utc() + chrono::Duration::try_days(1).unwrap();
		query!("INSERT INTO sessions (session_id, email, expires_at) VALUES (?, ?, ?) ON CONFLICT(session_id) DO UPDATE SET expires_at = ?",
				"valid_session_id",
				"valid@example.com",
				expiry,
				expiry,
			)
			.execute(db)
			.await
			.unwrap();

		// let req = test::TestRequest::get()
		// 	.uri("/")
		// 	.cookie(Cookie::new("session", "valid_session_id"))
		// 	.to_request();

		// let resp = test::call_service(&mut app, req).await;
		// assert_eq!(resp.status(), StatusCode::OK);

		let req = actix_test::TestRequest::get()
			.uri("/")
			.cookie(Cookie::new("session", "invalid_session_id"))
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

		let req = actix_test::TestRequest::get()
			.uri("/")
			.to_request();

		let resp = actix_test::call_service(&mut app, req).await;
		assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
	}
}
