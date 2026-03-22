use serde::{Deserialize, Serialize};
use sqlx::Row as _;
use tracing::*;

use crate::user::User;

#[async_trait::async_trait]
pub trait UserStore: Send + Sync {
	async fn from_email(&mut self, email: &str) -> Option<User>;
}

#[derive(Debug, Clone)]
pub enum UserStoreKind {
	Static(StaticUserStore),
	File(FileUserStore),
	SQL(SQLUserStore),
}

#[async_trait::async_trait]
impl UserStore for UserStoreKind {
	async fn from_email(&mut self, email: &str) -> Option<User> {
		match self {
			UserStoreKind::Static(store) => store.from_email(email).await,
			UserStoreKind::File(store) => store.from_email(email).await,
			UserStoreKind::SQL(store) => store.from_email(email).await,
		}
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticUserStore(Vec<User>);

impl StaticUserStore {
	pub fn new(users: Vec<User>) -> Self {
		Self(users)
	}
}

#[async_trait::async_trait]
impl UserStore for StaticUserStore {
	async fn from_email(&mut self, email: &str) -> Option<User> {
		self.0.iter().find(|user| user.email == email).cloned()
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileUserStore(String);

impl FileUserStore {
	pub fn new(path: String) -> Self {
		Self(path)
	}
}

#[async_trait::async_trait]
impl UserStore for FileUserStore {
	async fn from_email(&mut self, email: &str) -> Option<User> {
		let users_contents = match std::fs::read_to_string(self.0.clone()) {
			Ok(contents) => contents,
			Err(e) => {
				error!("Failed to read users file: {}", e);
				return None;
			}
		};
		let users = match serde_yaml::from_str::<Vec<User>>(&users_contents) {
			Ok(users) => users,
			Err(e) => {
				error!("Failed to parse users file: {}", e);
				return None;
			}
		};
		users.iter().find(|user| user.email == email).cloned()
	}
}

#[derive(Debug, Clone)]
pub struct SQLUserStore {
	conn: sqlx::AnyPool,
	#[allow(dead_code)]
	// This is not used but there's no way we won't need it at some point, right?
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
		// let Ok(conn) = self.conn.acquire().await else {
		// 	error!("Failed to acquire connection from the SQL user pool");
		// 	return None;
		// };

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
