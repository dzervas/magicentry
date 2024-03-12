use actix_session::Session;
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use log::info;
use sqlx::SqlitePool;
use jwt_simple::prelude::*;

use crate::user::User;
use crate::{Response, CONFIG};

pub mod model;
pub mod data;

use model::{OIDCAuth, OIDCSession};
use data::*;

pub async fn init(db: &SqlitePool) -> RS256KeyPair {
	if let Some(keypair) = crate::config::ConfigKV::get(&db, "jwt_keypair").await {
		RS256KeyPair::from_pem(&keypair).unwrap()
	} else {
		log::warn!("Generating JWT keypair for RSA 4096. This is going to take some time...");
		let keypair = RS256KeyPair::generate(4096).unwrap();
		let keypair_pem = keypair.to_pem().unwrap();

		crate::config::ConfigKV::set(&db, "jwt_keypair", &keypair_pem).await.unwrap_or_else(|_| panic!("Unable to set secret in the database"));

		keypair
	}
	.with_key_id("default")
}

#[get("/.well-known/openid-configuration")]
pub async fn configuration(req: HttpRequest) -> impl Responder {
	let discovery = Discovery::new(&CONFIG.url_from_request(&req));
	HttpResponse::Ok().json(discovery)
}

async fn authorize(session: Session, db: web::Data<SqlitePool>, data: AuthorizeRequest) -> Response {
	info!("Beginning OIDC flow for {}", data.client_id);
	session.insert("oidc_authorize", data.clone()).unwrap();

	let user = if let Some(user) = User::from_session(&db, session).await? {
		user
	} else {
		let target_url = format!("/login?{}", serde_qs::to_string(&data).unwrap());
		return Ok(HttpResponse::Found()
			.append_header(("Location", target_url))
			.finish())
	};

	let oidc_session = data.generate_code(&db, user.email.as_str()).await?;

	// TODO: Check the state with the cookie for CSRF
	// XXX: Open redirect
	let redirect_url = oidc_session.get_redirect_url();
	Ok(HttpResponse::Found()
		.append_header(("Location", redirect_url.as_str()))
		.finish())
	// Either send to ?code=<code>&state=<state>
	// Or send to ?error=<error>&error_description=<error_description>&state=<state>
}

#[get("/authorize")]
pub async fn authorize_get(session: Session, db: web::Data<SqlitePool>, data: web::Query<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
}

#[post("/authorize")]
pub async fn authorize_post(session: Session, db: web::Data<SqlitePool>, data: web::Form<AuthorizeRequest>) -> impl Responder {
	authorize(session, db, data.into_inner()).await
}

#[post("/token")]
pub async fn token(req: HttpRequest, db: web::Data<SqlitePool>, data: web::Form<TokenRequest>, key: web::Data<RS256KeyPair>) -> Response {
	let (client, session) = if let Some(client_session) = OIDCSession::from_code(&db, &data.code).await? {
		client_session
	} else {
		return Ok(HttpResponse::BadRequest().finish());
	};
	println!("Token Request: {:?}", data);

	if
		&client.id != data.client_id.as_ref().unwrap_or(&String::default()) ||
		&client.redirect_uri != data.redirect_uri.as_ref().unwrap_or(&String::default()) ||
		&client.secret != data.client_secret.as_ref().unwrap_or(&String::default()) {
		return Ok(HttpResponse::BadRequest().finish());
	}

	let jwt_data = JWTData {
		user: session.email.clone(),
		client_id: session.request.client_id.clone(),
		..JWTData::new(&CONFIG.url_from_request(&req))
	};
	println!("JWT Data: {:?}", jwt_data);

	let claims = Claims::with_custom_claims(jwt_data, Duration::from_millis(CONFIG.session_duration.num_milliseconds().try_into().unwrap()));
	let id_token = key.as_ref().sign(claims).unwrap();

	let access_token = OIDCAuth::generate(&db, session.email.clone()).await?.auth;

	Ok(HttpResponse::Ok().json(TokenResponse {
		access_token,
		token_type: "Bearer".to_string(),
		expires_in: CONFIG.session_duration.num_seconds(),
		id_token,
		refresh_token: None,
	}))
	// Either send to ?access_token=<token>&token_type=<type>&expires_in=<seconds>&refresh_token=<token>&id_token=<token>
	// Or send to ?error=<error>&error_description=<error_description>
}

#[get("/jwks")]
pub async fn jwks(key: web::Data<RS256KeyPair>) -> impl Responder {
	let comp = key.as_ref().public_key().to_components();

	let item = JWKSResponseItem {
		modulus: Base64::encode_to_string(comp.n).unwrap(),
		exponent: Base64::encode_to_string(comp.e).unwrap(),
		..Default::default()
	};

	let resp = JwksResponse {
		keys: vec![item],
	};

	HttpResponse::Ok().json(resp)
}

#[get("/userinfo")]
pub async fn userinfo(db: web::Data<SqlitePool>, req: HttpRequest) -> impl Responder {
	let auth_header = req.headers().get("Authorization").unwrap();
	let auth_header_parts = auth_header.to_str().unwrap().split_whitespace().collect::<Vec<&str>>();

	if auth_header_parts.len() != 2 || auth_header_parts[0] != "Bearer" {
		return HttpResponse::BadRequest().finish()
	}

	let auth = auth_header_parts[1];

	if let Ok(Some(user)) = OIDCAuth::get_user(&db, auth).await {
		let username = if let Some(alias) = user.username.clone() {
			alias
		} else {
			user.email.clone()
		};

		let resp = UserInfoResponse {
			user: user.email.clone(),
			email: user.email.clone(),
			preferred_username: username,
		};
		println!("Userinfo Response: {:?}", resp);

		HttpResponse::Ok().json(resp)
	} else {
		HttpResponse::Unauthorized().finish()
	}
}
