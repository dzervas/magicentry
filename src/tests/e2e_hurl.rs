#![allow(clippy::unwrap_used)]
#![cfg(feature = "e2e-test")]

use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use actix_web::{web, App, HttpServer};
use actix_web_httpauth::extractors::basic;
use glob::glob;
use tiny_http::{Response, Server as TinyServer};

use crate::config::ConfigFile;
use crate::secret::cleanup::spawn_cleanup_job;
use crate::*;

/// Starts a minimal static file server on 127.0.0.1:8081 serving the `hurl/.link.txt` file.
fn spawn_hurl_fixture_server() -> thread::JoinHandle<()> {
    thread::spawn(|| {
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let server = TinyServer::http(addr).expect("failed to bind tiny http server on :8081");
        for req in server.incoming_requests() {
            let url = req.url().to_string();
            if req.method().as_str() == "GET" && (url == "/.link.txt" || url.starts_with("/.link.txt?")) {
                let path = PathBuf::from("hurl/.link.txt");
                match std::fs::read(&path) {
                    Ok(body) => {
                        let mut resp = Response::from_data(body);
                        resp.add_header(tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/plain; charset=utf-8"[..]).unwrap());
                        let _ = req.respond(resp);
                    }
                    Err(_) => {
                        let _ = req.respond(Response::from_string("Not Found").with_status_code(404));
                    }
                }
            } else {
                let _ = req.respond(Response::from_string("Not Found").with_status_code(404));
            }
        }
    })
}

/// Boot the Actix server the same way as `src/main.rs`, but inline for tests.
async fn spawn_magicentry_server() -> actix_web::dev::Server {
    // Load config
    ConfigFile::reload().await.expect("load config");

    let config = CONFIG.read().await;
    let webauthn_enable = config.webauthn_enable;
    let listen_host = config.listen_host.clone();
    let listen_port = config.listen_port;
    let title = config.title.clone();
    let external_url = config.external_url.clone();

    // Init DB and side jobs
    let db = database::init_database(&config.database_url)
        .await
        .expect("init sqlite db");
    spawn_cleanup_job(db.clone());

    // Mailer and optional HTTP client
    // In tests, SmtpTransport is a stub; don't attempt real SMTP.
    let mailer: Option<SmtpTransport> = if config.smtp_enable {
        Some(lettre::transport::stub::AsyncStubTransport::new_ok())
    } else {
        None
    };

    let http_client = if config.request_enable {
        Some(reqwest::Client::new())
    } else {
        None
    };

    // OIDC
    let oidc_key = oidc::init(&db).await;
    drop(config);

    // Bind explicitly to ensure the port is available (fail fast in tests)
    let listener = TcpListener::bind(format!("{}:{}", listen_host, listen_port))
        .expect("bind server port");

    let server = HttpServer::new(move || {
        let mut app = App::new()
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(mailer.clone()))
            .app_data(web::Data::new(http_client.clone()))
            .app_data(basic::Config::default().realm("MagicEntry"))
            .default_service(web::route().to(error::not_found))
            .service(handle_index::index)
            .service(handle_login::login)
            .service(handle_login_post::login_post)
            .service(handle_magic_link::magic_link)
            .service(handle_logout::logout)
            .service(handle_static::static_files)
            .service(handle_static::favicon)
            // Auth URL
            .service(auth_url::handle_status::status)
            // SAML
            .service(saml::handle_metadata::metadata)
            .service(saml::handle_sso::sso)
            // OIDC
            .app_data(web::Data::new(oidc_key.clone()))
            .service(oidc::handle_discover::discover)
            .service(oidc::handle_discover::discover_preflight)
            .service(oidc::handle_authorize::authorize_get)
            .service(oidc::handle_authorize::authorize_post)
            .service(oidc::handle_token::token)
            .service(oidc::handle_token::token_preflight)
            .service(oidc::handle_userinfo::userinfo)
            .service(oidc::handle_jwks::jwks)
            .service(
                actix_web::web::redirect(
                    "/.well-known/oauth-authorization-server",
                    "/.well-known/openid-configuration",
                )
                    .permanent(),
            )
            .wrap(actix_web::middleware::Logger::default());

        if webauthn_enable {
            let webauthn = webauthn::init(&title, &external_url)
                .expect("create webauthn object");
            app = app
                .app_data(web::Data::new(webauthn))
                .service(webauthn::handle_reg_start::reg_start)
                .service(webauthn::handle_reg_finish::reg_finish)
                .service(webauthn::handle_auth_start::auth_start)
                .service(webauthn::handle_auth_finish::auth_finish);
        }

        app
    })
        .workers(1)
        .listen(listener)
        .unwrap()
        .run();

    server
}

/// Wait until the server is ready (responding to /login).
async fn wait_for_server_ready() {
    let client = reqwest::Client::new();
    for _ in 0..60u8 {
        if let Ok(resp) = client.get("http://127.0.0.1:8080/login").send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("server didn't become ready in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_e2e_hurl_specs() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Ensure we use the sample config and test feature path
    // TODO: This is unsafe??
    // std::env::set_var("CONFIG_FILE", "config.sample.yaml");

    // Spawn the tiny fixture server first (serves hurl/.link.txt on :8081)
    let _h = spawn_hurl_fixture_server();

    // Spawn app server
    let server = spawn_magicentry_server().await;
    let _srv_handle = tokio::spawn(server);

    // Wait until the server is healthy
    wait_for_server_ready().await;

    // Collect hurl spec files
    let mut specs: Vec<PathBuf> = vec![];
    for entry in glob("hurl/*.hurl").expect("glob hurl files") {
        match entry {
            Ok(path) => specs.push(path),
            Err(e) => panic!("glob error: {e}"),
        }
    }
    assert!(!specs.is_empty(), "no hurl specs found under ./hurl");

    // Run Hurl specs via the hurl crate library API
    use hurl::runner;
    use hurl::runner::{RunnerOptionsBuilder, VariableSet};
    use hurl::util::logger::LoggerOptionsBuilder;
    use hurl::util::path::ContextDir;
    use hurl_core::input::Input;

    let runner_opts = RunnerOptionsBuilder::new()
        .compressed(false)
        .fail_fast(false)
        .follow_location(false)
        .ignore_asserts(false)
        .insecure(false)
        .context_dir(&ContextDir::default())
        .build();

    let logger_opts = LoggerOptionsBuilder::new()
        .color(false)
        .verbosity(None)
        .build();

    let variables = VariableSet::new();

    for spec in specs {
        let content = std::fs::read_to_string(&spec)
            .unwrap_or_else(|e| panic!("failed to read {:?}: {}", &spec, e));
        let filename = Some(Input::new(spec.to_str().expect("non-utf8 hurl path not supported")));

        println!("Running {filename:?}");

        let result = runner::run(&content, filename.as_ref(), &runner_opts, &variables, &logger_opts)
            .unwrap_or_else(|e| panic!("hurl run failed for {:?}: {}", &spec, e));


        assert!(
            result.success,
            "hurl spec failed: {:?}\nerrors: {:?}",
            &spec,
            result
                .entries
                .iter()
                .flat_map(|e| e.errors.iter())
                .collect::<Vec<_>>()
        );

        // println!("Ran succeeded: {result:?}")
    }

    // Give a moment for any async shutdowns/logging to flush
    tokio::time::sleep(Duration::from_millis(50)).await;
}
