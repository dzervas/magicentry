//! Admin page template

use async_trait::async_trait;
use maud::{Markup, html};

use crate::secret::admin_token::AdminApiTokenSecret;

use super::Page;

/// Admin page data
pub struct AdminPage {
	pub admin_tokens: Vec<AdminApiTokenSecret>,
}

#[async_trait]
impl Page for AdminPage {
	fn render_partial(&self) -> Markup {
		html! {
			div class="bg-white dark:bg-gray-800 relative shadow-md sm:rounded-lg overflow-hidden" {
				div class="flex flex-col md:flex-row items-center justify-between space-y-3 md:space-y-0 md:space-x-4 p-4" {
					div class="w-full md:w-auto flex flex-col md:flex-row space-y-2 md:space-y-0 items-stretch md:items-center justify-end md:space-x-3 flex-shrink-0" {
						button type="button" class="flex items-center justify-center text-white bg-primary-700 hover:bg-primary-800 focus:ring-4 focus:ring-primary-300 font-medium rounded-lg text-sm px-4 py-2 dark:bg-primary-600 dark:hover:bg-primary-700 focus:outline-none dark:focus:ring-primary-800" {
							// TODO: Add icon
							"Add Token"
						}
					}
					div class="overflow-x-auto" {
						table class="w-full text-sm text-left text-gray-500 dark:text-gray-400" {
							thead class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-700 dark:text-gray-400" {
								tr {
									th scope="col" class="px-4 py-3" { "Token" }
									th scope="col" class="px-4 py-3" { "Description" }
									th scope="col" class="px-4 py-3" { "Created At" }
									th scope="col" class="px-4 py-3" { "Expires At" }
								}
							}
							tbody {
								@for token in &self.admin_tokens {
									tr class="border-b dark:border-gray-700" {
										td scope="row" class="px-4 py-3 font-medium text-gray-900 whitespace-nowrap dark:text-white" { (token.code().obfuscated()) }
										td class="px-4 py-3" { (token.metadata().description) }
										td class="px-4 py-3" { (token.created_at().to_string()) }
										td class="px-4 py-3" { (token.expires_at().to_string()) }
									}
								}
							}
						}
					}
				}
			}
		}
	}
}
