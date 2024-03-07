use actix_session::{Session, SessionMiddleware};
use actix_session::storage::CookieSessionStore;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, http::StatusCode, post, get};
use actix_web::cookie::Key;
use serde::Deserialize;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use lazy_static::lazy_static;
use rand::rngs::{OsRng, StdRng};
use rand::{Rng, RngCore, SeedableRng};
use hex;

use std::env;

pub mod schema;
pub mod config;

lazy_static! {
	static ref DATABASE_URL: String = env::var("DATABASE_URL").unwrap_or("database.sqlite3".to_string());
}

type DbPool = r2d2::Pool<ConnectionManager<SqliteConnection>>;

fn db_connect() -> DbPool {
	let manager = ConnectionManager::<SqliteConnection>::new(DATABASE_URL.as_str());
	r2d2::Pool::builder()
		.build(manager)
		.expect("Failed to create pool.")
}


// Define your email array
const VALID_EMAILS: [&str; 2] = ["email1@example.com", "email2@example.com"];

#[get("/")]
async fn index(session: Session, db: web::Data<&mut SqliteConnection>) -> impl Responder {
	if let Some(session_id) = session.get::<String>("session_id").unwrap_or(None) {
		return HttpResponse::Ok().finish()
	}
	HttpResponse::Unauthorized().finish()
}

#[get("/signin")]
async fn signin_get() -> impl Responder {
	// Render your HTML template for sign in
	HttpResponse::Ok().body("Signin page")
}

#[derive(Deserialize)]
struct SigninInfo {
	email: String,
}

#[post("/signin")]
async fn signin_post(info: web::Json<SigninInfo>, db: web::Data<DbPool>) -> impl Responder {
	if VALID_EMAILS.contains(&info.email.as_str()) {
		// let session_id = "hello";
		// Create a new session and add it to the database
		// let session_id = uuid::Uuid::new_v4().to_string();
		// let _ = sqlx::query!(
		// 	"INSERT INTO sessions (session_id, email, expires_at) VALUES (?, ?, datetime('now', '+1 day'))",
		// 	session_id,
		// 	info.email,
		// 	)
		// 	.execute(db.get_ref())
		// 	.await;

		// Send an email here with lettre
		// Assume we have a function `send_email(email: &str, session_link: &str)` that sends the email

		// let session_link = format!("/signin/{}", session_id);
		// send_email(&info.email, &session_link);

		HttpResponse::Ok().finish()
	} else {
		HttpResponse::Unauthorized().finish()
	}
}

#[get("/signin/{session}")]
async fn signin_session(session_id: web::Path<String>, session: Session, db: web::Data<DbPool>) -> impl Responder {
	// Set the session cookie
	// let valid_session = sqlx::query!(
	// 	"SELECT * FROM sessions WHERE session_id = ? AND expires_at > datetime('now')",
	// 	session_id.into_inner()
	// )
	// .fetch_optional(db_pool.get_ref())
	// .await
	// .unwrap();
	let valid_session = Some("hi");

	if valid_session.is_some() {
		// session.insert("session_id", valid_session.unwrap().session_id).unwrap();
		HttpResponse::Found().append_header(("Location", "/")).finish()
	} else {
		HttpResponse::Unauthorized().finish()
	}
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
	// let mut db_pool = SqliteConnection::establish("database.sqlite3").expect(format!("Unable to connect to sqlite database: `{}`", DATABASE_URL.as_str()).as_str());
	let db_pool = db_connect();
	let secret = if let Some(secret) = config::Config::get(db_pool.clone(), "secret") {
		let master = hex::decode(secret).unwrap();
		Key::from(&master)
	} else {
		let key = Key::generate();
		let master = hex::encode(key.master());

		config::Config::set(db_pool.clone(), "secret", &master).unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		key
	};

	HttpServer::new(move || {
		App::new()
			.app_data(web::Data::new(db_pool.clone()))
			.service(index)
			.service(signin_get)
			.service(signin_post)
			.service(signin_session)
			.wrap(SessionMiddleware::new(CookieSessionStore::default(), secret.clone())) // Use a better secret key in production
	})
	.bind("127.0.0.1:8080")?
	.run()
	.await
}
