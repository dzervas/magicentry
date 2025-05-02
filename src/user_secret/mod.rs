#![allow(async_fn_in_trait)]
pub mod secret;

// Secret types
pub mod browser_session;
pub mod link_login;

pub use browser_session::BrowserSessionSecret;
pub use link_login::LinkLoginSecret;
