use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use actix_web::cookie::{Key, SameSite};
use config::ConfigFile;
use serde::Deserialize;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use lazy_static::lazy_static;
use toml;

use std::env;

pub mod config;
pub mod schema;
pub mod user;

use user::{UserLink, UserSession};

pub(crate) const RANDOM_STRING_LEN: usize = 32;

lazy_static! {
	static ref LISTEN_HOST: String = env::var("LISTEN_HOST").unwrap_or("127.0.0.1".to_string());
	static ref LISTEN_PORT: String = env::var("LISTEN_PORT").unwrap_or("8080".to_string());
	static ref DATABASE_URL: String = env::var("DATABASE_URL").unwrap_or("database.sqlite3".to_string());
	static ref SESSION_TIME: String = env::var("SESSION_TIME").unwrap_or("1d".to_string());
	static ref CONFIG_FILE: String = env::var("CONFIG_FILE").unwrap_or("config.toml".to_string());
	static ref CONFIG: ConfigFile = toml::from_str(
		&std::fs::read_to_string(CONFIG_FILE.as_str())
			.expect(format!("Unable to open config file `{:?}`", CONFIG_FILE.as_str()).as_str())
		).expect(format!("Unable to parse config file `{:?}`", CONFIG_FILE.as_str()).as_str());
	// static ref SMTP_HOST: String = env::var("SESSION_TIME").unwrap_or("1d".to_string());
	// static ref SMTP_HOST: String = env::var("SESSION_TIME").unwrap_or("1d".to_string());
}

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;
type DbConn = r2d2::PooledConnection<ConnectionManager<SqliteConnection>>;

#[get("/")]
async fn index(session: Session, db: web::Data<DbPool>) -> impl Responder {
	let conn = &mut db.get().unwrap();
	let session_id = if let Some(session) = session.get::<String>("session").unwrap_or(None) {
		session
	} else {
		return HttpResponse::Unauthorized().finish()
	};


	let _session = if let Some(session) = UserSession::from_id(conn, &session_id) {
		session
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	HttpResponse::Ok().finish()
}

#[get("/signin")]
async fn signin_get() -> impl Responder {
	// Render your HTML template for sign in
	HttpResponse::Ok().body("Signin page")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
struct SigninInfo {
	email: String,
}


#[post("/signin")]
async fn signin_post(form: web::Form<SigninInfo>, db: web::Data<DbPool>) -> impl Responder {
	let conn = &mut db.get().unwrap();
	let user = if let Some(user) = CONFIG.users.iter().find_map(|u| if u.email == form.email { Some(u) } else { None }) {
		user
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	let session = UserSession::new(conn, &user);
	println!("Session: {:?}", session);

	// Send an email here with lettre
	// Assume we have a function `send_email(email: &str, session_link: &str)` that sends the email

	// let session_link = format!("/signin/{}", session_id);
	// send_email(&info.email, &session_link);

	HttpResponse::Ok().finish()
}

#[get("/signin/{magic}")]
async fn signin_session(magic: web::Path<String>, session: Session, db: web::Data<DbPool>) -> impl Responder {
	let conn = &mut db.get().unwrap();
	let user = if let Some(user) = UserLink::visit(conn, magic.clone()) {
		user
	} else {
		return HttpResponse::Unauthorized().finish()
	};

	let user_session = UserSession::new(conn, &user);
	session.insert("session", user_session.session_id).unwrap();

	HttpResponse::Found().append_header(("Location", "/")).finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	let manager = ConnectionManager::<SqliteConnection>::new(DATABASE_URL.as_str());
	let db = r2d2::Pool::builder().build(manager).expect("Failed to create database connection pool.");
	let secret = if let Some(secret) = config::ConfigKV::get(db.clone(), "secret") {
		let master = hex::decode(secret).unwrap();
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		config::ConfigKV::set(db.clone(), "secret", &master).unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		key
	};

	HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(db.clone()))
			.service(index)
			.service(signin_get)
			.service(signin_post)
			.service(signin_session)
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
