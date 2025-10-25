//! Page rendering errors

use thiserror::Error;

/// Page rendering-related errors
#[derive(Debug, Error)]
pub enum PageError {
    #[error("Page rendering error: {message}")]
    Render { message: String },

    #[error("Template error: {message}")]
    Template { message: String },

    #[error("Page not found: {page}")]
    NotFound { page: String },

    #[error("Invalid page data: {data}")]
    InvalidData { data: String },
}

impl PageError {
    /// Create a render error with a custom message
    pub fn render(message: impl Into<String>) -> Self {
        Self::Render {
            message: message.into(),
        }
    }

    /// Create a template error with a custom message
    pub fn template(message: impl Into<String>) -> Self {
        Self::Template {
            message: message.into(),
        }
    }

    /// Create a not found error with a custom message
    pub fn not_found(page: impl Into<String>) -> Self {
        Self::NotFound {
            page: page.into(),
        }
    }

    /// Create an invalid data error with a custom message
    pub fn invalid_data(data: impl Into<String>) -> Self {
        Self::InvalidData {
            data: data.into(),
        }
    }
}
