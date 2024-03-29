# Installation

## Standalone

MagicEntry can be used as a standalone application.

Download the latest release from the [releases page](https://github.com/dzervas/magicentry/releases).

You most probably need the non `-kube` version (the `-kube` has Kubernetes capabilities -
for running MagicEntry in Kuberentes see the [relevant section](usge.md#kubernetes)).

```bash
./magicentry
```

This will start the MagicEntry server on port 8080 with the default configuration,
overwritten by the yaml config pointed to by `$CONFIG_FILE` (defaults to `config.yaml`).

For configuration check out the [Configuration](configuration.md) section.

## Docker

MagicEntry is also available as a Docker image:

```bash
docker run -p 127.0.0.1:8080:8080 ghcr.io/dzervas/magicentry:latest
```

again the default configuration is used, but you can mount your own configuration file:

```bash
docker run -v $(pwd)/config.yaml:/config.yaml -p 127.0.0.1:8080:8080 ghcr.io/dzervas/magicentry:latest
```

## Kuberentes

You can use the official helm chart to deploy MagicEntry in Kubernetes:

```bash
helm install --update --namespace auth --values values.yaml magicentry oci://ghcr.io/dzervas/charts/magicentry
```

For the values check out the chart's [values.yaml](https://github.com/dzervas/magicentry/blob/main/chart/values.yaml).

### Example values.yaml

```yaml
ingress:
  enabled: true
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      location /oidc/token {
      deny all;
      return 403;
      }
  hosts:
  - host: auth.example.com
    paths:
    - path: /
      pathType: Prefix
  # Make sure that the secret `auth-dzerv-art-cert` exists or gets created by cert-manager
  tls:
  - hosts:
    - auth.example.com
    secretName: auth-example-com-cert
persistence:
  enabled: true
  size: 1Gi

config:
  title: Example Auth Service
  external_url: "https://auth.example.com"
  auth_url_enable: true
  request_enable: true # Defaults to CI Notify

  oidc_enable: true
  oidc_clients:
  - id: SFOSOtKaOgwdnSkEyeDiztJE5LY0AMZJ0feDezV2620 # Generated with `gpg --gen-random 2 32 | basenc --base64url -w 0`
    secret: zwn7k2Vj-Ux5K382lTPbDbeckDEsrpIWDfPVdV07RLOdrOYGIxLP5z25t6Y7J_1wwJ07rfRU_XeKF3ODCj6NGQ # Generated with `gpg --gen-random 2 64 | basenc --base64url -w 0`
    redirect_uris:
    - https://myservice.example.com/auth/openid/callback
    realms:
    - myservice

  users:
  - name: My Awesome Name
    email: awesome@example.com
    username: awesome
    realms:
    # `all` is a special realm that allows access to all realms
    # for more check out the [realms](./realms.md) section
    - all
  - name: A guest
    email: guest@example.com
    username: guest
    realms:
    - myservice
```

To make an ingress resource use the `auth.example.com` as [auth-url](https://kubernetes.github.io/ingress-nginx/examples/auth/oauth-external-auth/)
you can add the following annotations to the ingress resource:

```yaml
magicentry.rs/realms: myservice
magicentry.rs/auth-url: "true"
nginx.ingress.kubernetes.io/auth-url: "http://magicentry.auth.svc.cluster.local:8080/auth-url/status"
nginx.ingress.kubernetes.io/auth-signin: "https://auth.example.com/login"
nginx.ingress.kubernetes.io/server-snippet: |
  location = /__magicentry_auth_code {
      add_header Set-Cookie "code=$arg_code; Path=/; HttpOnly; Secure; Max-Age=60; SameSite=Lax";
      return 302 /;
  }
```
