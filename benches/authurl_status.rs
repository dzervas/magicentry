use actix_web::{web, App};
use actix_web::test::{call_service, init_service, TestRequest};
use actix_web::dev::ServiceResponse;
use actix_web::cookie::Cookie;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use magicentry::{CONFIG, PROXY_SESSION_COOKIE};
use magicentry::user_secret::{BrowserSessionSecret, EmptyMetadata};
use magicentry::user_secret::proxy_session::ProxySessionSecret;
use magicentry::user::User;
use magicentry::config::ConfigFile;
use magicentry::auth_url::{self};
use reindeer::{Db, Entity};

pub async fn db_connect() -> Db {
	let db = reindeer::open(&CONFIG.read().await.database_url)
		.expect("Failed to open reindeer database.");
	magicentry::user_secret::register(&db).unwrap();
	magicentry::config::ConfigKV::register(&db).expect("Failed to register config_kv entity");

	db
}

async fn setup_app(db: &Db) -> impl actix_web::dev::Service<
	actix_http::Request,
	Response = ServiceResponse,
	Error = actix_web::Error,
> {
	init_service(
		App::new()
			.app_data(web::Data::new(db.clone()))
			.service(auth_url::handle_status::status)
	).await
}

pub async fn get_valid_user() -> User {
	ConfigFile::reload()
		.await
		.expect("Failed to reload config file");
	let user_email = "valid@example.com";
	let user_realms = vec!["example".to_string()];
	let config = CONFIG.read().await;
	let user = config.users.iter().find(|u| u.email == user_email).unwrap();

	assert_eq!(user.email, user_email);
	assert_eq!(user.realms, user_realms);

	user.to_owned()
}

fn bench_status_endpoint(c: &mut Criterion) {
	// Setup the runtime for async code
	let rt = tokio::runtime::Runtime::new().unwrap();

	let (app, proxy_session) = rt.block_on(async {
		let db = db_connect().await;
		let app = setup_app(&db).await;
		let user = get_valid_user().await;
		let browser_session = BrowserSessionSecret::new(user, EmptyMetadata(), &db).await.unwrap();
		let proxy_session = ProxySessionSecret::new_child(
			browser_session,
			EmptyMetadata(),
			&db,
		).await.unwrap();

		(app, proxy_session)
	});

	let mut group = c.benchmark_group("authurl_status");
	group.throughput(criterion::Throughput::Elements(1));


	group.bench_function("auth_url_status_with_session", |b| {
		b.to_async(&rt).iter(|| async {
			let req = TestRequest::get()
				.uri("/auth-url/status")
				.cookie(Cookie::new(PROXY_SESSION_COOKIE, proxy_session.code().to_str_that_i_wont_print()))
				.to_request();

			black_box(call_service(&app, req).await)
		});
	});

	group.bench_function("auth_url_status_unauthorized", |b| {
		b.to_async(&rt).iter(|| async {
			let req = TestRequest::get()
				.uri("/auth-url/status")
				.to_request();

			black_box(call_service(&app, req).await)
		});
	});
}

criterion_group!(benches, bench_status_endpoint);
criterion_main!(benches);
