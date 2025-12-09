use chrono::Utc;

use std::time::Duration as StdDuration;

/// Delete all expired secrets from the database.
///
/// A secret is considered expired when `expires_at <= now()`.
pub async fn cleanup_expired(db: &crate::Database) -> anyhow::Result<()> {
	// TODO: Re-calculate expiration based on the config
	let now = Utc::now().naive_utc();
	sqlx::query!("DELETE FROM user_secrets WHERE expires_at <= ?", now)
		.execute(db)
		.await?;

	Ok(())
}

pub fn spawn_cleanup_job(db: crate::Database) {
	tokio::spawn(async move {
		loop {
			if let Err(e) = cleanup_expired(&db).await {
				tracing::error!("Failed to cleanup expired secrets: {e}");
			} else {
				tracing::info!("Expired secrets cleanup completed");
			}

			// Read interval from config each cycle to pick up reloads
			let sleep_dur: StdDuration = {
				let cfg = crate::CONFIG.read().await;
				cfg.secrets_cleanup_interval
					.to_std()
					.unwrap_or_else(|_| StdDuration::from_secs(24 * 60 * 60))
			};
			tracing::debug!("Next expired secrets cleanup in {sleep_dur:?}");
			tokio::time::sleep(sleep_dur).await;
		}
	});
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::{database::init_database, error::AppError};

	async fn setup_test_db() -> Result<crate::Database, AppError> {
		init_database("sqlite::memory:").await
	}

	#[tokio::test]
	async fn deletes_only_expired() {
		use sqlx::Row;

		let db = setup_test_db().await.unwrap();

		sqlx::query!(
			"INSERT INTO user_secrets (code, user, expires_at) VALUES (?, ?, datetime('now', '-1 hour'))",
			"mc_ll_expiredSecret",
			r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#,
		)
		.execute(&db)
		.await
		.unwrap();

		sqlx::query!(
			"INSERT INTO user_secrets (code, user, expires_at) VALUES (?, ?, datetime('now', '+1 hour'))",
			"mc_ll_validSecret",
			r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#,
		)
		.execute(&db)
		.await
		.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets WHERE code='mc_ll_validSecret'")
			.fetch_one(&db)
			.await
			.unwrap();
		assert!(!row.is_empty(), "There should be a row in the DB");
		let row = sqlx::query("SELECT * FROM user_secrets WHERE code='mc_ll_expiredSecret'")
			.fetch_one(&db)
			.await
			.unwrap();
		assert!(!row.is_empty(), "There should be a row in the DB");

		cleanup_expired(&db).await.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets WHERE code='mc_ll_validSecret'")
			.fetch_one(&db)
			.await
			.unwrap();
		assert!(!row.is_empty(), "There should be a row in the DB");
		let row = sqlx::query("SELECT * FROM user_secrets WHERE code='mc_ll_expiredSecret'")
			.fetch_one(&db)
			.await;
		assert!(row.is_err(), "There should NOT be a row in the DB");
	}

	#[tokio::test]
	async fn deletes_boundary_equal_now() {
		use sqlx::Row;

		let db = setup_test_db().await.unwrap();

		sqlx::query!(
			"INSERT INTO user_secrets (code, user, expires_at) VALUES (?, ?, datetime('now'))",
			"mc_ll_nowSecret",
			r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#,
		)
		.execute(&db)
		.await
		.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets")
			.fetch_one(&db)
			.await
			.unwrap();
		assert!(!row.is_empty(), "There should be a row in the DB");

		cleanup_expired(&db).await.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets")
			.fetch_one(&db)
			.await;
		assert!(row.is_err(), "There should NOT be a row in the DB");
	}

	#[tokio::test]
	async fn no_op_when_none_expired() {
		use sqlx::Row;

		let db = setup_test_db().await.unwrap();

		sqlx::query!(
			"INSERT INTO user_secrets (code, user, expires_at) VALUES (?, ?, datetime('now', '-1 hour'))",
			"mc_ll_expiredSecret",
			r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#,
		)
		.execute(&db)
		.await
		.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets")
			.fetch_one(&db)
			.await
			.unwrap();
		assert!(!row.is_empty(), "There should be a row in the DB");

		cleanup_expired(&db).await.unwrap();

		let row = sqlx::query("SELECT * FROM user_secrets")
			.fetch_one(&db)
			.await;
		assert!(row.is_err(), "There should NOT be a row in the DB");
	}
}
