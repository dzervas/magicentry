# Login and create an API key
GET http://localhost:8080/login
HTTP 200
[Asserts]
xpath "//form[@method='post']" count == 1

POST http://localhost:8080/login
[Form]
email: valid@example.com
HTTP 200

GET http://localhost:8081/.link.txt
HTTP 200
[Captures]
link: body

GET {{link}}
HTTP 302
Location: /
[Captures]
session: cookie "session_id"

POST http://localhost:8080/api_key
[Cookies]
session_id: {{session}}
[Form]
service: example
expiration: 60
HTTP 200
[Captures]
created_key: xpath "//code[@id='api-key']/text()"

# Use created key
GET http://localhost:8080/auth-url/status
[Headers]
X-Original-URL: http://localhost:8081/
X-Api-Key: {{created_key}}
HTTP 200

# Rotate key
POST http://localhost:8080/api_key/rotate
[Cookies]
session_id: {{session}}
[Form]
key: {{created_key}}
HTTP 200
[Captures]
rotated_key: xpath "//code[@id='api-key']/text()"

# Old key should fail
GET http://localhost:8080/auth-url/status
[Headers]
X-Original-URL: http://localhost:8081/
X-Api-Key: {{created_key}}
HTTP 401

# New key should succeed
GET http://localhost:8080/auth-url/status
[Headers]
X-Original-URL: http://localhost:8081/
X-Api-Key: {{rotated_key}}
HTTP 200

# Delete new key
POST http://localhost:8080/api_key/delete
[Cookies]
session_id: {{session}}
[Form]
key: {{rotated_key}}
HTTP 302
Location: /

# Deleted key should fail
GET http://localhost:8080/auth-url/status
[Headers]
X-Original-URL: http://localhost:8081/
X-Api-Key: {{rotated_key}}
HTTP 401

GET http://localhost:8080/
[Cookies]
session_id: {{session}}
HTTP 200
[Asserts]
body contains "API Keys"
