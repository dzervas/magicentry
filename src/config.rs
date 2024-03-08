use std::collections::HashMap;

use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::schema::config;
use crate::schema::config::dsl::*;
use crate::user::User;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfigFile {
	pub users: Vec<User>,
}

impl From<ConfigFileRaw> for ConfigFile {
	fn from(raw: ConfigFileRaw) -> Self {
		let users = raw
			.users
			.into_iter()
			.map(|(email, realms)| User { email, realms })
			.collect();

		ConfigFile { users }
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFileRaw {
	pub users: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Queryable, Selectable)]
#[diesel(table_name = crate::schema::config)]
pub struct ConfigKV {
	pub key: String,
	pub value: Option<String>,
}

impl ConfigKV {
	pub fn get(db: crate::DbPool, name: &str) -> Option<String> {
		let mut conn = db.get().unwrap();
		let record = config
			.filter(key.eq(name))
			.limit(1)
			.load::<ConfigKV>(&mut conn)
			.unwrap_or(Vec::new());

		if let Some(record) = record.get(0) {
			record.value.clone()
		} else {
			None
		}
	}

	pub fn set(db: crate::DbPool, name: &str, new_value: &str) -> Result<usize, diesel::result::Error> {
		let mut conn = db.get().unwrap();
		diesel::update(config::table)
			.filter(key.eq(name))
			.set(value.eq(new_value))
			.execute(&mut conn)
	}
}
