//! Pages module for maud HTML templates
//!
//! This module provides compile-time HTML templates using maud to replace
//! the handlebars templates. Each template uses minimal, semantic HTML
//! without styling or helper tags.

pub mod authorize;
pub mod error;
pub mod index;
pub mod login;
pub mod login_action;
pub mod page_trait;
pub mod partials;

#[cfg(doc)]
pub mod example;

// Re-export commonly used types and functions
pub use authorize::*;
pub use error::*;
pub use index::*;
pub use login::*;
pub use login_action::*;
pub use page_trait::*;
pub use partials::*;

// Re-export PageError for convenience
pub use crate::error::PageError;
