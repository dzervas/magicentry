use serde::Deserialize;
use sqlx::Row as _;
use tracing::*;

use crate::domain::user::User;

#[async_trait::async_trait]
pub trait UserStore {
	async fn from_email(&mut self, email: &str) -> Option<User>;
}

#[derive(Debug, Clone)]
pub enum UserStoreType {
	Config(ConfigUserStore),
	SQL(SQLUserStore),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConfigUserStore(Vec<User>);

impl ConfigUserStore {
	pub fn new(users: Vec<User>) -> Self {
		ConfigUserStore(users)
	}
}

#[async_trait::async_trait]
impl UserStore for ConfigUserStore {
	async fn from_email(&mut self, email: &str) -> Option<User> {
		self.0.iter().find(|user| user.email == email).cloned()
	}
}

#[derive(Debug, Clone)]
pub struct SQLUserStore {
	conn: sqlx::AnyPool,
	query_all: String,
	query_email: String,
}

impl SQLUserStore {
	pub fn new(url: &str, query_all: String, query_email: String) -> anyhow::Result<Self> {
		sqlx::any::install_default_drivers();
		Ok(Self {
			conn: sqlx::AnyPool::connect_lazy(url)?,
			query_all,
			query_email,
		})
	}
}

#[async_trait::async_trait]
impl UserStore for SQLUserStore {
	async fn from_email(&mut self, email: &str) -> Option<User> {
		let row_result = sqlx::query(&self.query_email)
			.bind(email)
			.fetch_one(&self.conn)
			.await;
		let row = match row_result {
			Ok(row) => row,
			Err(err) => {
				warn!("Failed to fetch user by email: {}", err);
				return None;
			}
		};

		let Ok(username) = row.try_get(0) else {
			error!("Failed to get username from the SQL user pool's email query result");
			return None;
		};
		let Ok(name) = row.try_get(1) else {
			error!("Failed to get name from the SQL user pool's email query result");
			return None;
		};
		let Ok(email) = row.try_get(2) else {
			error!("Failed to get email from the SQL user pool's email query result");
			return None;
		};
		let realms = row
			.try_get(3)
			.and_then(|r: String| Ok(r.split(",").map(|s| s.to_string()).collect::<Vec<String>>()))
			.unwrap_or_default();

		Some(User {
			username,
			email,
			name,
			realms,
		})
	}
}
