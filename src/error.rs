use actix_web::{error::ResponseError, HttpResponse, http::StatusCode};
use std::fmt;

#[derive(Debug, Clone)]
pub struct Error {
	cause: String,
}

impl From<sqlx::Error> for Error {
	fn from(error: sqlx::Error) -> Self {
		log::error!("Database error: {:?}", error);

		#[cfg(debug_assertions)]
		return Error { cause: format!("Internal Server Error: {}", error) };

		#[cfg(not(debug_assertions))]
		return Error { cause: format!("Internal Server Error", error) };
	}
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "{}", self.cause)
	}
}

impl ResponseError for Error {
	fn status_code(&self) -> StatusCode {
		StatusCode::INTERNAL_SERVER_ERROR
	}

	fn error_response(&self) -> HttpResponse {
		HttpResponse::InternalServerError().content_type("text/html").body("Internal Server Error - Please try again later.")
	}
}
