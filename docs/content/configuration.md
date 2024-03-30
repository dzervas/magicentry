---
title: Configuration
weight: 10
---

MagicEntry is configured via a yaml file. You can check out the complete
default configuration [here](https://github.com/dzervas/magicentry/blob/main/config.sample.yaml).

The default configuration file name is `config.yaml` and is expected to be in the
same directory as the binary. You can override this by setting the `CONFIG_FILE`
environment variable.

Any configuration option in `CONFIG_FILE` essentially overrides the default
values of `config.sample.yaml`.

## Minimum viable configuration

```yaml
listen_host: 0.0.0.0
request_enable: true # Send magic links using CINotify

users:
  - username: admin
    name: Admin User
    email: admin@example.com
    realms:
      - all
  - username: valid
    name: Valid User
    email: valid@example.com
    realms:
      - example
  - username: integration
    email: valid-integration@example.com
    name: Integration User
    realms:
      - example
      - public
```
