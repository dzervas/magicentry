use chrono::Utc;

use std::time::Duration as StdDuration;

use crate::error::Result;

/// Delete all expired secrets from the database.
///
/// A secret is considered expired when `expires_at <= now()`.
pub async fn cleanup_expired(db: &crate::Database) -> Result<()> {
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
				log::error!("Failed to cleanup expired secrets: {e}");
			} else {
				log::info!("Expired secrets cleanup completed");
			}

			// Read interval from config each cycle to pick up reloads
			let sleep_dur: StdDuration = {
				let cfg = crate::CONFIG.read().await;
				cfg.secrets_cleanup_interval
					.to_std()
					.unwrap_or_else(|_| StdDuration::from_secs(24 * 60 * 60))
			};
			log::debug!("Next expired secrets cleanup in {sleep_dur:?}");
			tokio::time::sleep(sleep_dur).await;
		}
	});
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::Duration;

	use crate::secret::LoginLinkSecret;
	use crate::database::init_database;

	async fn setup_test_db() -> crate::error::Result<crate::Database> {
		init_database("sqlite::memory:").await
	}

	#[tokio::test]
	async fn deletes_only_expired() {
		let db = setup_test_db().await.unwrap();

		sqlx::query("INSERT INTO user_secrets (code, user, expires_at, metadata) VALUES (?, ?, ?, ?)")
			.bind("mc_ll_expiredSecret")
			.bind(r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#)
			.bind(Utc::now().naive_utc() - Duration::hours(1))
			.bind("{}")
			.execute(&db)
			.await
			.unwrap();

		sqlx::query("INSERT INTO user_secrets (code, user, expires_at, metadata) VALUES (?, ?, ?, ?)")
			.bind("mc_ll_validSecret")
			.bind(r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#)
			.bind(Utc::now().naive_utc() + Duration::hours(1))
			.bind("{}")
			.execute(&db)
			.await
			.unwrap();

		assert!(LoginLinkSecret::try_from_string("mc_ll_expiredSecret".to_string(), &db).await.is_ok());
		assert!(LoginLinkSecret::try_from_string("mc_ll_validSecret".to_string(), &db).await.is_ok());

		cleanup_expired(&db).await.unwrap();

		assert!(LoginLinkSecret::try_from_string("mc_ll_expiredSecret".to_string(), &db).await.is_err());
		assert!(LoginLinkSecret::try_from_string("mc_ll_validSecret".to_string(), &db).await.is_ok());
	}

	#[tokio::test]
	async fn deletes_boundary_equal_now() {
		let db = setup_test_db().await.unwrap();

		sqlx::query("INSERT INTO user_secrets (code, user, expires_at, metadata) VALUES (?, ?, ?, ?)")
			.bind("mc_ll_nowSecret")
			.bind(r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#)
			.bind(Utc::now().naive_utc())
			.bind("{}")
			.execute(&db)
			.await
			.unwrap();

		assert!(LoginLinkSecret::try_from_string("mc_ll_nowSecret".to_string(), &db).await.is_ok());

		cleanup_expired(&db).await.unwrap();
		assert!(LoginLinkSecret::try_from_string("mc_ll_nowSecret".to_string(), &db).await.is_err());
	}

	#[tokio::test]
	async fn no_op_when_none_expired() {
		let db = setup_test_db().await.unwrap();

		sqlx::query("INSERT INTO user_secrets (code, user, expires_at, metadata) VALUES (?, ?, ?, ?)")
			.bind("mc_ll_nowSecret")
			.bind(r#"{"email":"hello@world.com","username":"helloworld","name":"Hello World","realms":["test"]}"#)
			.bind(Utc::now().naive_utc() + Duration::hours(1))
			.bind("{}")
			.execute(&db)
			.await
			.unwrap();

		assert!(LoginLinkSecret::try_from_string("mc_ll_nowSecret".to_string(), &db).await.is_ok());

		cleanup_expired(&db).await.unwrap();
		assert!(LoginLinkSecret::try_from_string("mc_ll_nowSecret".to_string(), &db).await.is_ok());
	}
}

