use actix_web::http::header::ContentType;
use actix_web::{error::ResponseError, HttpResponse, http::StatusCode};
use derive_more::{Display, Error};

pub type SqlResult<T> = std::result::Result<T, sqlx::Error>;
pub type Response = std::result::Result<HttpResponse, Error>;

#[derive(Debug, Display, Error, Clone)]
pub enum AppErrorKind {
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

impl ResponseError for AppErrorKind {
	fn status_code(&self) -> StatusCode {
		match self {
			AppErrorKind::MissingAuthorizationHeader => StatusCode::BAD_REQUEST,
			AppErrorKind::CouldNotParseAuthorizationHeader => StatusCode::BAD_REQUEST,
			AppErrorKind::InvalidClientID => StatusCode::UNAUTHORIZED,
			AppErrorKind::NoClientID => StatusCode::BAD_REQUEST,
			AppErrorKind::NoClientSecret => StatusCode::BAD_REQUEST,
			_ => StatusCode::BAD_REQUEST,
		}
	}

	fn error_response(&self) -> HttpResponse {
		let status = self.status_code();
		if status.as_u16() < 500 {
			log::warn!("{}", self)
		} else {
			log::error!("{}", self)
		}

		HttpResponse::build(status)
			.content_type(ContentType::html())
			.body(self.to_string())
	}
}

#[derive(Debug, Display, Error, Clone)]
#[cfg_attr(debug_assertions, display(fmt = "Internal Server Error: {}", cause))]
#[cfg_attr(not(debug_assertions), display(fmt = "Internal Server Error"))]
pub struct Error {
	cause: String,
	app_error: Option<AppErrorKind>,
}

impl ResponseError for Error {
	fn status_code(&self) -> StatusCode {
		if let Some(app_error) = &self.app_error {
			app_error.status_code()
		} else {
			StatusCode::INTERNAL_SERVER_ERROR
		}
	}

	fn error_response(&self) -> HttpResponse {
		if let Some(app_error) = &self.app_error {
			app_error.error_response()
		} else {
			log::error!("{}", self.cause);
			HttpResponse::InternalServerError()
				.content_type(ContentType::html())
				.body(self.to_string())
		}
	}
}

impl From<String> for Error {
	fn from(error: String) -> Self {
		Self {
			cause: error,
			app_error: None,
		}
	}
}

impl From<AppErrorKind> for Error {
	fn from(error: AppErrorKind) -> Self {
		Self {
			cause: String::default(),
			app_error: Some(error),
		}
	}
}

impl From<actix_session::SessionGetError> for Error {
	fn from(error: actix_session::SessionGetError) -> Self {
		format!("Session Get error: {}", error).into()
	}
}

impl From<actix_session::SessionInsertError> for Error {
	fn from(error: actix_session::SessionInsertError) -> Self {
		format!("Session Insert error: {}", error).into()
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
