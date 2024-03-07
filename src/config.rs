use diesel::prelude::*;

use crate::schema::config;
use crate::schema::config::dsl::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::config)]
#[diesel(check_for_backend(diesel::sqlite::Sqlite))]
pub struct Config {
	pub key: String,
	pub value: Option<String>,
}

impl Config {
	pub fn get(db: crate::DbPool, name: &str) -> Option<String> {
		let mut conn = db.get().unwrap();
		let record = config
			.filter(key.eq(name))
			.limit(1)
			.load::<Config>(&mut conn)
			.unwrap_or(Vec::new());

		if let Some(record) = record.get(0) {
			record.value.clone()
		} else {
			None
		}
	}

	pub fn set(db: crate::DbPool, name: &str, new_value: &str) -> Result<usize, diesel::result::Error> {
		diesel::update(config::table)
			.filter(key.eq(name))
			.set(value.eq(new_value))
			.execute(&mut db.get().unwrap())
	}
}
