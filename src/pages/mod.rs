//! Pages module for maud HTML templates
//!
//! This module provides compile-time HTML templates using maud to replace
//! the handlebars templates. Each template uses minimal, semantic HTML
//! without styling or helper tags.

pub mod page_trait;
pub mod partials;
pub mod error;
pub mod login;
pub mod login_action;
pub mod index;
pub mod authorize;

#[cfg(doc)]
pub mod example;

// Re-export commonly used types and functions
pub use page_trait::*;
pub use partials::*;
pub use error::*;
pub use login::*;
pub use login_action::*;
pub use index::*;
pub use authorize::*;

// Re-export PageError for convenience
pub use crate::error::PageError;