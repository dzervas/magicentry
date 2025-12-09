//! Database-related errors

use thiserror::Error;

/// Database operation errors
#[derive(Debug, Error)]
pub enum DatabaseError {
	#[error("Database connection failed: {source}")]
	Connection { source: sqlx::Error },
	#[error("Database migration failed: {source}")]
	Migration { source: sqlx::migrate::MigrateError },
	#[error("Database query failed: {source}")]
	Query { source: sqlx::Error },
	#[error("Unable to access the database instance during request parsing")]
	InstanceError,
	#[error("Database operation failed: {operation}")]
	Operation { operation: String },
}

impl DatabaseError {
	/// Create a query error from a [`sqlx::Error`]
	pub const fn query(source: sqlx::Error) -> Self {
		Self::Query { source }
	}

	/// Create a connection error from a [`sqlx::Error`]
	pub const fn connection(source: sqlx::Error) -> Self {
		Self::Connection { source }
	}

	/// Create a migration error from a [`sqlx::migrate::MigrateError`]
	pub const fn migration(source: sqlx::migrate::MigrateError) -> Self {
		Self::Migration { source }
	}

	/// Create an operation error with a custom message
	pub fn operation(operation: impl Into<String>) -> Self {
		Self::Operation {
			operation: operation.into(),
		}
	}
}
