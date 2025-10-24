//! Example: Render all pages to HTML files
//!
//! This example demonstrates how to use the Page trait to render all
//! page types and export them as HTML files for inspection.

use std::path::Path;
use std::fs;
use crate::config::ConfigFile;
use crate::pages::*;

/// Mock configuration for testing
fn create_mock_config() -> ConfigFile {
    ConfigFile {
        database_url: "sqlite::memory:".to_string(),
        listen_host: "127.0.0.1".to_string(),
        listen_port: 8080,
        path_prefix: "/demo".to_string(),
        external_url: "http://localhost:8080".to_string(),
        link_duration: chrono::Duration::try_hours(12).unwrap(),
        session_duration: chrono::Duration::try_days(30).unwrap(),
        secrets_cleanup_interval: chrono::Duration::try_hours(24).unwrap(),
        title: "MagicEntry Demo".to_string(),
        static_path: "static".to_string(),
        auth_url_enable: true,
        auth_url_user_header: "X-Remote-User".to_string(),
        auth_url_email_header: "X-Remote-Email".to_string(),
        auth_url_name_header: "X-Remote-Name".to_string(),
        auth_url_realms_header: "X-Remote-Realms".to_string(),
        oidc_code_duration: chrono::Duration::try_minutes(1).unwrap(),
        saml_cert_pem_path: "saml_cert.pem".to_string(),
        saml_key_pem_path: "saml_key.pem".to_string(),
        smtp_enable: false,
        smtp_url: "smtp://localhost:25".to_string(),
        smtp_from: "{title} <magicentry@example.com>".to_string(),
        smtp_subject: "{title} Login".to_string(),
        smtp_body: "Click the link to login: {magic_link}".to_string(),
        request_enable: false,
        request_url: "https://www.cinotify.cc/api/notify".to_string(),
        request_method: "POST".to_string(),
        request_data: Some("to={email}&subject={title} Login&body=Click the link to login: <a href=\"{magic_link}\">Login</a>&type=text/html".to_string()),
        request_content_type: "application/x-www-form-urlencoded".to_string(),
        webauthn_enable: true,
        users_file: None,
        users: vec![],
        services: crate::service::Services(vec![]),
    }
}

/// Helper function to render pages with mock config
async fn render_with_mock_config<P>(page: P, filename: &str) -> Result<(), Box<dyn std::error::Error>>
where
    P: Page,
{
    // For this example, we'll simulate the global CONFIG with a local Arc<RwLock>
    // In a real application, the global CONFIG would be properly initialized

    // Create a mock config and use it directly with render_partial
    let mock_config = create_mock_config();

    // Manually implement the render logic using the mock config
    let content = page.render_partial(&mock_config).await?;

    // Create layout and render full page
    let layout = crate::pages::partials::PageLayout {
        title: page.get_title(&mock_config).to_string(),
        path_prefix: page.get_path_prefix(&mock_config).to_string(),
    };

    let html = crate::pages::partials::render_page(&layout, &content);
    save_html(filename, &html.into_string())?;

    Ok(())
}

/// Create output directory
fn ensure_output_dir() -> Result<(), std::io::Error> {
    let output_dir = Path::new("rendered_pages");
    if output_dir.exists() {
        fs::remove_dir_all(output_dir)?;
    }
    fs::create_dir_all(output_dir)?;
    Ok(())
}

/// Save HTML content to file
fn save_html(filename: &str, content: &str) -> Result<(), std::io::Error> {
    let filepath = Path::new("rendered_pages").join(filename);
    fs::write(filepath, content)?;
    println!("✅ Saved: {filename}");
    Ok(())
}

/// Render and save error page
async fn render_error_page() -> Result<(), Box<dyn std::error::Error>> {
    let error_page = ErrorPage {
        code: "404".to_string(),
        error: "Page Not Found".to_string(),
        description: "The page you're looking for doesn't exist.".to_string(),
    };

    render_with_mock_config(error_page, "error.html").await
}

/// Render and save login page
async fn render_login_page() -> Result<(), Box<dyn std::error::Error>> {
    let login_page = LoginPage;

    render_with_mock_config(login_page, "login.html").await
}

/// Render and save login action page
async fn render_login_action_page() -> Result<(), Box<dyn std::error::Error>> {
    let login_action_page = LoginActionPage;

    render_with_mock_config(login_action_page, "login_action.html").await
}

/// Render and save index page
async fn render_index_page() -> Result<(), Box<dyn std::error::Error>> {
    let index_page = IndexPage {
        email: "user@example.com".to_string(),
        services: vec![
            ServiceInfo {
                name: "Service 1".to_string(),
                url: "https://service1.example.com".to_string(),
            },
            ServiceInfo {
                name: "Service 2".to_string(),
                url: "https://service2.example.com".to_string(),
            },
            ServiceInfo {
                name: "Internal Dashboard".to_string(),
                url: "https://dashboard.example.com".to_string(),
            },
        ],
    };

    render_with_mock_config(index_page, "index.html").await
}

/// Render and save authorization page (OIDC)
async fn render_authorize_page_oidc() -> Result<(), Box<dyn std::error::Error>> {
    let auth_page = AuthorizePage {
        client: "OAuth Client".to_string(),
        name: "John Doe".to_string(),
        username: "johndoe".to_string(),
        email: "john@example.com".to_string(),
        saml_response_data: None,
        saml_relay_state: None,
        saml_acs: None,
        link: Some("https://oauth.example.com/callback?code=abc123&state=xyz789".to_string()),
    };

    render_with_mock_config(auth_page, "authorize_oidc.html").await
}

/// Render and save authorization page (SAML)
async fn render_authorize_page_saml() -> Result<(), Box<dyn std::error::Error>> {
    let auth_page = AuthorizePage {
        client: "SAML Service Provider".to_string(),
        name: "Jane Smith".to_string(),
        username: "janesmith".to_string(),
        email: "jane@example.com".to_string(),
        saml_response_data: Some("PHNhbWxQYXJhbWV0ZXMgU3RhdHVzPSJTdWNjZXNzIiB8IEB4bWwgc3RhdGljIGRlY2xhcmF0aW9ucz0iZWFzeSI+PC9zYW1sUGFyYW1ldGVycz4=".to_string()), // Mock SAML response
        saml_relay_state: Some("relay_state_123".to_string()),
        saml_acs: Some("https://saml.example.com/saml/acs".to_string()),
        link: None,
    };

    render_with_mock_config(auth_page, "authorize_saml.html").await
}

/// Create an index page to view all rendered examples
fn create_viewer_index() -> Result<(), std::io::Error> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MagicEntry Pages - rendered examples</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .page-list { list-style: none; padding: 0; }
        .page-list li { margin: 10px 0; }
        .page-list a {
            display: block;
            padding: 15px;
            background: #f5f5f5;
            border: 1px solid #ddd;
            border-radius: 5px;
            text-decoration: none;
            color: #333;
            transition: background-color 0.2s;
        }
        .page-list a:hover { background: #e9e9e9; }
        .description {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
            font-style: italic;
        }
        .note {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <h1>MagicEntry Pages - Rendered Examples</h1>

    <div class="note">
        <strong>Note:</strong> These are basic HTML renderings without styling.
        The actual pages would have CSS styling applied from the main.css file.
    </div>

    <h2>Available Pages:</h2>
    <ul class="page-list">
        <li>
            <a href="error.html">
                <strong>Error Page (404)</strong>
                <div class="description">Shows error handling with custom error messages</div>
            </a>
        </li>
        <li>
            <a href="login.html">
                <strong>Login Page</strong>
                <div class="description">User login form with email input and WebAuthn support</div>
            </a>
        </li>
        <li>
            <a href="login_action.html">
                <strong>Login Action Page</strong>
                <div class="description">Shown after user submits login form (email sent)</div>
            </a>
        </li>
        <li>
            <a href="index.html">
                <strong>Index Page</strong>
                <div class="description">Main dashboard after successful login with service list</div>
            </a>
        </li>
        <li>
            <a href="authorize_oidc.html">
                <strong>OAuth Authorization Page</strong>
                <div class="description">OAuth2/OIDC consent screen for third-party apps</div>
            </a>
        </li>
        <li>
            <a href="authorize_saml.html">
                <strong>SAML Authorization Page</strong>
                <div class="description">SAML consent screen with form submission</div>
            </a>
        </li>
    </ul>

    <h2>Page Trait Features:</h2>
    <ul>
        <li>✅ Async rendering with automatic config integration</li>
        <li>✅ Type-safe custom structs for each page type</li>
        <li>✅ Compile-time HTML validation with maud</li>
        <li>✅ Minimal, semantic HTML without styling</li>
        <li>✅ Config values (title, path_prefix) from global CONFIG</li>
        <li>✅ Backward compatibility with legacy render functions</li>
    </ul>
</body>
</html>"#;

    save_html("viewer.html", html)
}

#[tokio::test]
async fn render_pages() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Starting MagicEntry Page Rendering Example");
    println!("=====================================");

    // Create output directory
    ensure_output_dir()?;
    println!("📁 Created output directory: rendered_pages/");

    // Render all pages using the new Page trait
    println!("\n📄 Rendering pages with Page trait:");

    render_error_page().await?;
    render_login_page().await?;
    render_login_action_page().await?;
    render_index_page().await?;
    render_authorize_page_oidc().await?;
    render_authorize_page_saml().await?;

    // Create viewer index
    create_viewer_index()?;

    println!("\n✨ All pages rendered successfully!");
    println!("\n📂 Open 'rendered_pages/viewer.html' in your browser to see all examples");
    println!("🌐 Each page shows the basic HTML structure without CSS styling");
    println!("🔗 The actual pages would have full styling from main.css");
    println!("🚀 Pages are rendered using the new async Page trait with config integration");

    Ok(())
}
