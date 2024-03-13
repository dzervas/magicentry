# Just Passwordless

A simple authentication proxy which focuses on passwordless authentication.

The only way for a user to log in is a magic link sent to them.

Link sending is done via email or an HTTP request.

The proxy is designed to be used in conjunction with a reverse proxy such as
Nginx or Traefik to provide a full authentication solution or as an OIDC/OAuth 2.0
provider.
