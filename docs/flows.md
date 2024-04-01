# Flows

This page describes the available paths of interaction that a user or client can take.

"Client" is any third-party application that uses the API and "user" is a browser and is considered a physical person.

## Global Login

This flow describes the login process that a user needs to take to gain access to any user-bound resource.

There's no other path that a user can take to authenticate themselves.

1. (Optional) Visit the index (`GET /`) and get redirected to `/login`
2. (Optional) View the page that contains the form to initiate the login process (`GET /login`)
3. Post the user's email address (`POST /login`) in a form-data format with the email having the input name `email`
    - A "magic link" should be delivered to the user by some means (HTTP request, e-mail, etc.)
4. (Optional) View the resulting success message, regardless of the actual existence of the user (to avoid leaking valid email addresses)
5. Visit the magic link (`GET /link/{magic}`), gain a valid session (cookie for example)
    - The session and the link should be valid only for the same user that initiated the flow
    - The session and the link should not be valid after the first visit
    - The link should be valid for a limited amount of time, enough to allow for possible delivery latency (e.g. 4 hours for possible email gray-listing)
    - The session should be valid for a limited amount of time

## Global Logout

This flow describes the flow that allows a user to invalidate its current session.

There's no other path that a user can take to un-authenticate themselves.

1. Visit the logout page (`GET /logout`)
    - The session ID gained during login should no longer be valid
    - Delete the session storage (e.g. cookie) that the ID is held

## Global Status

This is the page that shows the current state of the authenticated user

1. Visit the index page (`GET /`)
    - Show the current user name, email, username
    - Show the current global sessions, scoped sessions and client authorizations (TODO)

## Scoped Login

This flow is targeted for clients and not for users.

This allows any configured client to be able to authenticate the user while hosted under a different domain
thus maintaining the secrecy of the global session (which would give total control of the user's data to the client)

The most common use case is to alter a proxy's responses according to the authentication status of the user

For example using [ingress-nginx](https://kubernetes.github.io/ingress-nginx/) to show a private page only to users that are authenticated for `hello.example.com` using the [auth-url](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/) annotation.

1. (Optional) Visit the target application (`https://hello.example.com/`)
2. Redirect the user to the login page with the target scope as a url-encoded query parameter (`GET /login?scope=https%3A%2F%2Fhello.example.com%2F`)
    - The target application URL should be checked against the possible valid applications (e.g. from the config file)
3. Set the scope in a user-faced storage (e.g. cookie)
4. (if the user does not have a valid global session) Initiate and finish the [Global Login flow](#global-login)
5. Redirect the user back to the application according to the scope while passing a scoped session code as a query parameter (`https://hello.example.com/?code=<scoped-code>`)
    - A scoped session code must abide by the scoped session rules described in [Global Login](#global-login)
    - A scoped session code must only be valid for requests that their headers `X-Original-Url` and `Referer` point to a sub-directory of the path (`https://hello.example.com`)
    - A scoped session code must be bound to the global session that it was created from and it can't out-live it
    - A scoped session code must be valid for a very short amount of time (until the proxy is able to set it as a cookie and the service can replace it)
    - A scoped session code must only be valid for one time use

## Scoped Login - long term session

As the [Scoped Login](#scoped-login) flow generates a valid scoped session that is leaked through a GET request, the generated scoped session code must get replaced by a different scoped session transfered during the first use of the code

1. Request the status of the user's authentication (`GET /status`) with the appropriate `X-Original-Url` and `Referer` headers (e.g. through a [rewrite](https://kubernetes.github.io/ingress-nginx/examples/rewrite/))
    - If it's the first request after the [Scoped Login flow](#scoped-login), an accompanied scoped session code must be transferred through a cookie (`scoped_session_code`) and a new long-lived scoped session cookie should be sent to the user that is valid for the appropriate target URL
      - The new scoped session must be valid for as long as the bound global session is valid for
      - The new scoped session must be valid for the exact host AND path that the proxy checks the status (e.g. the rewrite target, `https://hello.example.com/auth-status`)
      - The old scoped session code should no longer be valid
    - If it's any follow-up request the scoped session should be validated and on success return `HTTP OK 200`
