use chrono::Utc;

use std::time::Duration as StdDuration;

use crate::error::Result;

/// Delete all expired secrets from the database.
///
/// A secret is considered expired when `expires_at <= now()`.
pub async fn cleanup_expired(db: &crate::Database) -> Result<()> {
	let now = Utc::now().naive_utc();
	sqlx::query("DELETE FROM user_secrets WHERE expires_at <= ?")
		.bind(now)
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

	use crate::database::{init_database, UserSecretRow, UserSecretType};

	async fn setup_test_db() -> crate::error::Result<crate::Database> {
		init_database("sqlite::memory:").await
	}

	#[tokio::test]
	async fn deletes_only_expired() {
		let db = setup_test_db().await.unwrap();

		let expired = UserSecretRow {
			id: "expired_secret".to_string(),
			secret_type: UserSecretType::LoginLink,
			user_data: r#"{"email":"test@example.com","username":"test","name":"Test User","realms":["test"]}"#.to_string(),
			expires_at: Utc::now().naive_utc() - Duration::hours(1),
			metadata: "{}".to_string(),
			created_at: None,
		};

		let valid = UserSecretRow {
			id: "valid_secret".to_string(),
			secret_type: UserSecretType::LoginLink,
			user_data: r#"{"email":"test@example.com","username":"test","name":"Test User","realms":["test"]}"#.to_string(),
			expires_at: Utc::now().naive_utc() + Duration::hours(1),
			metadata: "{}".to_string(),
			created_at: None,
		};

		expired.save(&db).await.unwrap();
		valid.save(&db).await.unwrap();

		assert!(UserSecretRow::exists("expired_secret", &db).await.unwrap());
		assert!(UserSecretRow::exists("valid_secret", &db).await.unwrap());

		cleanup_expired(&db).await.unwrap();

		assert!(!UserSecretRow::exists("expired_secret", &db).await.unwrap());
		assert!(UserSecretRow::exists("valid_secret", &db).await.unwrap());
	}

	#[tokio::test]
	async fn deletes_boundary_equal_now() {
		let db = setup_test_db().await.unwrap();

		let boundary = UserSecretRow {
			id: "boundary_secret".to_string(),
			secret_type: UserSecretType::LoginLink,
			user_data: r#"{"email":"test@example.com","username":"test","name":"Test User","realms":["test"]}"#.to_string(),
			expires_at: Utc::now().naive_utc(),
			metadata: "{}".to_string(),
			created_at: None,
		};

		boundary.save(&db).await.unwrap();
		assert!(UserSecretRow::exists("boundary_secret", &db).await.unwrap());

		cleanup_expired(&db).await.unwrap();
		assert!(!UserSecretRow::exists("boundary_secret", &db).await.unwrap());
	}

	#[tokio::test]
	async fn no_op_when_none_expired() {
		let db = setup_test_db().await.unwrap();

		let valid1 = UserSecretRow {
			id: "valid1".to_string(),
			secret_type: UserSecretType::LoginLink,
			user_data: r#"{"email":"test@example.com","username":"test","name":"Test User","realms":["test"]}"#.to_string(),
			expires_at: Utc::now().naive_utc() + Duration::hours(2),
			metadata: "{}".to_string(),
			created_at: None,
		};
		valid1.save(&db).await.unwrap();

		cleanup_expired(&db).await.unwrap();

		assert!(UserSecretRow::exists("valid1", &db).await.unwrap());
	}
}

