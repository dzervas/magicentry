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

GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Cookies]
session_id: {{session}}
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
state: "<hello/>
HTTP 200
[Captures]
# authcode: xpath "//a[@data-modal-toggle='successListModal']/@href"
authcode: regex "code=(me_oa_\\w+)&"
[Asserts]
# Basic XSS Check
body not contains "<hello"
body contains "https://openidconnect.net/callback?code=me_oa_"

POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{authcode}}
client_id: my_client
client_secret: my_secret
redirect_uri: {{redirect urlEncode}}
HTTP 200
[Captures]
token: jsonpath "$.access_token"
[Asserts]
jsonpath "$.token_type" == "Bearer"


GET {{base_url}}/oidc/userinfo
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.sub" == "valid@example.com"
jsonpath "$.email" == "valid@example.com"
jsonpath "$.name" == "Valid User"
jsonpath "$.preferred_username" == "valid"
jsonpath "$.email_verified" == true

# Test the authorization redirect
# Clear the cookies: https://github.com/Orange-OpenSource/hurl/discussions/1740#discussioncomment-6386769
# @cookie_storage_clear
GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
HTTP 303
[Captures]
login: header "Location"

# Click the "Login" button in the UI that the proxy redirected us to
POST {{login}}
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
[Asserts]
header "Location" startsWith "/oidc/authorize?"
[Captures]
session: cookie "session_id"
authorize_link: header "Location"

GET {{base_url}}{{authorize_link}}
[Cookies]
session_id: {{session}}
HTTP 200
[Asserts]
body contains "https://openidconnect.net/callback?code=me_oa_"

# A redirect registered to one client must not be accepted for another client.
GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Cookies]
session_id: {{session}}
[Query]
client_id: admin_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256
HTTP 400

# The handler currently stores the rejected code before validating the redirect. Retrieve it
# through the test-only fixture to verify that token exchange still rejects the unauthorized user.
GET {{base_url}}/oidc-authcode
HTTP 200
[Captures]
rejected_cross_client_authcode: body

POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{rejected_cross_client_authcode}}
client_id: admin_client
code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
HTTP 401

# A valid PKCE flow succeeds.
GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Cookies]
session_id: {{session}}
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256
HTTP 200
[Captures]
pkce_authcode: regex "code=(me_oa_\\w+)&"

POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{pkce_authcode}}
client_id: my_client
code_verifier: dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
HTTP 200
[Asserts]
jsonpath "$.token_type" == "Bearer"

# Client credentials cannot bypass a PKCE challenge when the verifier is missing.
GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Cookies]
session_id: {{session}}
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
code_challenge: E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method: S256
HTTP 200
[Captures]
pkce_authcode_without_verifier: regex "code=(me_oa_\\w+)&"

POST {{base_url}}/oidc/token
[Form]
grant_type: authorization_code
code: {{pkce_authcode_without_verifier}}
client_id: my_client
client_secret: my_secret
HTTP 400
[Asserts]
body contains "PKCE request is missing the code_verifier form field"

# Basic credentials for a different client cannot change the client bound to the code.
GET {{base_url}}/oidc/authorize
[Options]
variable: redirect="https://openidconnect.net/callback"
[Cookies]
session_id: {{session}}
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
HTTP 200
[Captures]
basic_authcode: regex "code=(me_oa_\\w+)&"

POST {{base_url}}/oidc/token
Authorization: Basic YWRtaW5fY2xpZW50OmFkbWluX3NlY3JldA==
[Form]
grant_type: authorization_code
code: {{basic_authcode}}
HTTP 401
