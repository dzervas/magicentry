#![allow(
	clippy::unwrap_used,
	clippy::missing_panics_doc,
	clippy::missing_errors_doc,
	clippy::future_not_send
)]

use std::hint::black_box;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::http::StatusCode;
use axum_extra::extract::cookie::Cookie;
use axum_test::TestServer;
use criterion::{Criterion, criterion_group, criterion_main};

use magicentry::app_build::axum_build;
use magicentry::config::{Config, LiveConfig};
use magicentry::database::init_database;
use magicentry::secret::{BrowserSessionSecret, EmptyMetadata, ProxySessionSecret};
use magicentry::user_store::UserStore;
use magicentry::{CONFIG_FILE, PROXY_ORIGIN_HEADER, PROXY_SESSION_COOKIE};

async fn setup_bench() -> (TestServer, String) {
	let config = Config::reload_from_path(&CONFIG_FILE).await.unwrap();
	let mut user_store = config.get_user_store().unwrap();
	let user = user_store.from_email("valid@example.com").await.unwrap();
	let live_config = LiveConfig(Arc::new(config.clone()));
	let config = Arc::new(ArcSwap::new(Arc::new(config)));
	let db = init_database("sqlite::memory:").await.unwrap();
	let app = axum_build(db.clone(), config, vec![], None).await;
	let server = TestServer::builder().http_transport().build(app).unwrap();

	let browser_session = BrowserSessionSecret::new(user, EmptyMetadata(), &live_config, &db)
		.await
		.unwrap();
	let proxy_session =
		ProxySessionSecret::new_child(browser_session, EmptyMetadata(), &live_config, &db)
			.await
			.unwrap();

	(
		server,
		proxy_session.code().to_str_that_i_wont_print().to_owned(),
	)
}

fn bench_status_endpoint(c: &mut Criterion) {
	let rt = tokio::runtime::Runtime::new().unwrap();
	let (server, proxy_session_cookie) = rt.block_on(setup_bench());

	let mut group = c.benchmark_group("authurl_status");
	group.throughput(criterion::Throughput::Elements(1));
	group.bench_function("proxy_session_ok", |b| {
		b.to_async(&rt).iter(|| async {
			let response = black_box(
				server
					.get("/auth-url/status")
					.add_header(PROXY_ORIGIN_HEADER, "http://localhost:8080/")
					.add_cookie(Cookie::new(
						PROXY_SESSION_COOKIE,
						proxy_session_cookie.clone(),
					))
					.await,
			);

			assert_eq!(response.status_code(), StatusCode::OK);
		});
	});
	group.bench_function("proxy_session_err", |b| {
		b.to_async(&rt).iter(|| async {
			let response = black_box(
				server
					.get("/auth-url/status")
					.add_header(PROXY_ORIGIN_HEADER, "http://localhost:8080/")
					.await,
			);

			assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
		});
	});
	group.finish();
}

criterion_group!(benches, bench_status_endpoint);
criterion_main!(benches);
