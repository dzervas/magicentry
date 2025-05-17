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

GET http://localhost:8080/oidc/authorize
[Options]
variable: redirect=https://openidconnect.net/callback
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
authcode: regex "code=(me_oidc_authcode_\\w+)&"
[Asserts]
# Basic XSS Check
body not contains "<hello"
body contains "https://openidconnect.net/callback?code=me_oidc_authcode_"

POST http://localhost:8080/oidc/token
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


GET http://localhost:8080/oidc/userinfo
Authorization: Bearer {{token}}
HTTP 200
[Asserts]
jsonpath "$.sub" == "valid@example.com"
jsonpath "$.email" == "valid@example.com"
jsonpath "$.name" == "Valid User"
jsonpath "$.preferred_username" == "valid"
jsonpath "$.email_verified" == true

# Test the authorization redirect
# GET http://localhost:8080/oidc/authorize
# [Options]
# variable: redirect=https://openidconnect.net/callback
# [Query]
# client_id: my_client
# redirect_uri: {{redirect urlEncode}}
# scope: openid
# response_type: code
# HTTP 302
# [Captures]
# login: header "Location"

# # Click the "Login" button in the UI that the proxy redirected us to
# POST {{login}}
# [Form]
# email: valid@example.com
# HTTP 200

# # Set up a temporary webserver to serve the login link
# # python3 -m http.server -d hurl 8081
# GET http://localhost:8081/.link.txt
# HTTP 200
# [Captures]
# link: body

# # Visit the magic link that was sent
# GET {{link}}
# HTTP 302
# [Asserts]
# header "Location" startsWith "/oidc/authorize?"
# [Captures]
# session: cookie "session_id"
# authorize_link: header "Location"

# GET http://localhost:8080/{{authorize_link}}
# [Cookies]
# session_id: {{session}}
# HTTP 200
