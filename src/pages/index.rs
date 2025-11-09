//! Index page template (shown after successful login)

use async_trait::async_trait;
use maud::{Markup, html};

use super::{script, Page};

/// Service information for index page
#[derive(Debug, Clone)]
pub struct ServiceInfo {
	pub name: String,
	pub url: String,
}

/// Index page data
#[derive(Debug, Clone)]
pub struct IndexPage {
	pub email: String,
	pub services: Vec<ServiceInfo>,
}

#[async_trait]
impl Page for IndexPage {
	fn render_partial(&self) -> Markup {
		html! {
			div class="relative p-4 w-full max-w-md h-full md:h-auto" {
				div class="relative p-4 text-center bg-white rounded-lg shadow-sm dark:bg-gray-800 sm:p-5" {
					div class="w-12 h-12 rounded-full bg-green-100 dark:bg-green-900 p-2 flex items-center justify-center mx-auto mb-3.5" {
						svg aria-hidden="true" class="w-8 h-8 text-green-500 dark:text-green-400" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg" {
							path
							fill-rule="evenodd"
							d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z"
							clip-rule="evenodd" {}
						}
						span class="sr-only" { "Success" }
					}

					p class="mb-4 text-lg font-semibold text-gray-900 dark:text-white" { (format!("Welcome back {}", self.email)) }
					p class="mb-4 text-md text-gray-900 dark:text-white" { "You're all set!" }
					a href="/logout" type="button" class="py-2 px-3 m-2 text-sm font-medium text-center text-white rounded-lg bg-rose-800 hover:bg-rose-700 focus:ring-4 focus:outline-hidden focus:ring-rose-300 dark:focus:ring-rose-900" { "Logout" }
					button id="webauthn-register" type="button" class="hidden py-2 px-3 m-2 text-sm font-medium text-center text-white rounded-lg bg-primary-800 hover:bg-primary-700 focus:ring-4 focus:outline-hidden focus:ring-primary-300 dark:focus:ring-primary-900" { "Register PassKey" }
				}
			}

			div class="relative p-8 w-full max-w-md h-full md:h-auto" {
				table class="w-full text-sm text-left text-gray-500 dark:text-gray-400 rounded-lg" {
					tbody {
						@for service in &self.services {
							tr class="odd:bg-white odd:dark:bg-gray-900 even:bg-gray-50 even:dark:bg-gray-800 border-b dark:border-gray-700 border-gray-200 hover:bg-gray-50 dark:hover:bg-gray-600" {
								th scope="row" class="flex items-center px-6 py-4 text-gray-900 whitespace-nowrap dark:text-white" {
									object data=(format!("{}/favicon.ico", service.url.trim_end_matches('/'))) type="image/x-icon"  class="w-10 h-10 rounded-full" {
										img src=("/static/app-placeholder.svg") class="w-10 h-10 rounded-full bg-primary-800" {}
									}
									div  class="ps-3" {
										a href=(&service.url) class="no-underline" {
											div class="text-base font-semibold" { (&service.name) }
										}
										div class="font-normal text-gray-500" { "realm" }
									}
								}
							}
							td class="px-6 py-4" {
								div class="flex-shrink-0 w-6 h-6" {}
							}
						}
					}
				}
			}
			(script("webauthn"))
		}
	}
}
