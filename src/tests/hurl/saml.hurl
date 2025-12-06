# Click the "login" button
POST {{base_url}}/login
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET {{fixture_url}}
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{base_url}}{{link}}
HTTP 303
Location: /
[Captures]
session: cookie "session_id"

# TODO: Use a normal XML SAML request (b64 encoded, deflated too?)
# GET {{base_url}}/saml/sso
# [Cookies]
# session_id: {{session}}
# [Query]
# request: example
# HTTP 200
# [Captures]
# authcode: regex "code=(me_oa_\\w+)&"
#
# # Test the authorization redirect
# GET {{base_url}}/saml/sso
# [Options]
# variable: redirect=https://openidconnect.net/callback
# [Query]
# client_id: my_client
# redirect_uri: {{redirect urlEncode}}
# scope: openid
# response_type: code
# HTTP 303
# [Captures]
# login: header "Location"
#
# # Click the "Login" button in the UI that the proxy redirected us to
# POST {{login}}
# [Form]
# email: valid@example.com
# HTTP 200
#
# # Set up a temporary webserver to serve the login link
# # python3 -m http.server -d hurl 8081
# GET {{fixture_url}}
# HTTP 200
# [Captures]
# link: body
#
# # Visit the magic link that was sent
# GET {{link}}
# HTTP 303
# [Asserts]
# header "Location" startsWith "/oidc/authorize?"
# [Captures]
# session: cookie "session_id"
# authorize_link: header "Location"
#
# GET {{base_url}}{{authorize_link}}
# [Cookies]
# session_id: {{session}}
# HTTP 200
# [Asserts]
# body contains "https://openidconnect.net/callback?code=me_oa_"
