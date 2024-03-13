use actix_web::http::header::ContentType;
use actix_web::{error::ResponseError, HttpResponse, http::StatusCode};
use derive_more::{Display, Error};

pub type SqlResult<T> = std::result::Result<T, sqlx::Error>;

#[derive(Debug, Display, Error, Clone)]
pub enum ErrorKind {
	#[display(fmt = "Missing Authorization header")]
	MissingAuthorizationHeader,
	#[display(fmt = "Could not parse Authorization header")]
	CouldNotParseAuthorizationHeader,
	#[display(fmt = "The Duration provided is incorrect or too big (max i64)")]
	InvalidDuration,
	#[display(fmt = "Client sent a redirect URL different from the one in the config")]
	IncorrectRedirectUrl,
	#[display(fmt = "Client sent a client_id that is not in the config")]
	InvalidClientID,
	#[display(fmt = "Client did not send a client_id")]
	NoClientID,
	#[display(fmt = "Client did not send a client_secret")]
	NoClientSecret,
}

#[derive(Debug, Display, Error, Clone)]
#[cfg_attr(debug_assertions, display(fmt = "Internal Server Error: {}", cause))]
#[cfg_attr(not(debug_assertions), display(fmt = "Internal Server Error"))]
pub struct Error {
	cause: String,
}

impl ResponseError for Error {
	fn status_code(&self) -> StatusCode {
		StatusCode::INTERNAL_SERVER_ERROR
	}

	fn error_response(&self) -> HttpResponse {
		HttpResponse::InternalServerError()
			.content_type(ContentType::html())
			.body(self.to_string())
	}
}

impl From<String> for Error {
	fn from(error: String) -> Self {
		log::error!("{}", error);
		return Error { cause: error };
	}
}

impl From<ErrorKind> for Error {
	fn from(error: ErrorKind) -> Self {
		format!("Application error: {}", error).into()
	}
}

impl From<sqlx::Error> for Error {
	fn from(error: sqlx::Error) -> Self {
		format!("Database error: {}", error).into()
	}
}

impl From<formatx::Error> for Error {
	fn from(error: formatx::Error) -> Self {
		format!("Formatting error: {}", error).into()
	}
}

impl From<lettre::error::Error> for Error {
	fn from(error: lettre::error::Error) -> Self {
		format!("Lettre error: {}", error).into()
	}
}

impl From<lettre::transport::stub::Error> for Error {
	fn from(error: lettre::transport::stub::Error) -> Self {
		format!("Lettre (Stub transport) error: {}", error).into()
	}
}

impl From<lettre::transport::smtp::Error> for Error {
	fn from(error: lettre::transport::smtp::Error) -> Self {
		format!("Lettre (SMTP transport) error: {}", error).into()
	}
}

impl From<lettre::address::AddressError> for Error {
	fn from(error: lettre::address::AddressError) -> Self {
		format!("Lettre Address error: {}", error).into()
	}
}

impl From<reqwest::Error> for Error {
	fn from(error: reqwest::Error) -> Self {
		format!("Reqwest error: {}", error).into()
	}
}

impl From<serde_qs::Error> for Error {
	fn from(error: serde_qs::Error) -> Self {
		format!("Serde-qs error: {}", error).into()
	}
}

impl From<jwt_simple::Error> for Error {
	fn from(error: jwt_simple::Error) -> Self {
		format!("JWT Simple error: {}", error).into()
	}
}

impl From<jwt_simple::reexports::ct_codecs::Error> for Error {
	fn from(error: jwt_simple::reexports::ct_codecs::Error) -> Self {
		format!("CT Codecs error: {}", error).into()
	}
}
