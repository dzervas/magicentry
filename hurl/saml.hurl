# Click the "login" button
POST http://localhost:8080/login
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{link}}
HTTP 302
Location: /
[Captures]
session: cookie "session_id"

GET http://localhost:8080/saml/sso
[Cookies]
session_id: {{session}}
[Query]
request: asdf
HTTP 200
[Captures]
authcode: regex "code=(me_oidc_authcode_\\w+)&"

# Test the authorization redirect
GET http://localhost:8080/saml/sso
[Options]
variable: redirect=https://openidconnect.net/callback
[Query]
client_id: my_client
redirect_uri: {{redirect urlEncode}}
scope: openid
response_type: code
HTTP 302
[Captures]
login: header "Location"

# Click the "Login" button in the UI that the proxy redirected us to
POST {{login}}
[Form]
email: valid@example.com
HTTP 200

# Set up a temporary webserver to serve the login link
# python3 -m http.server -d hurl 8081
GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

# Visit the magic link that was sent
GET {{link}}
HTTP 302
[Asserts]
header "Location" startsWith "/oidc/authorize?"
[Captures]
session: cookie "session_id"
authorize_link: header "Location"

GET http://localhost:8080{{authorize_link}}
[Cookies]
session_id: {{session}}
HTTP 200
[Asserts]
body contains "https://openidconnect.net/callback?code=me_oidc_authcode_"
