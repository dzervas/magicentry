---
title: MagicEntry
weight: 1
---

MagicEntry is a simple identity provider. Its target use case is for hobbyists
and small organizations that need a simple way to manage user accounts and access
to web applications. The only way to authenticate is by using magic links sent
through email or using passkeys.

It has small footprint, is easy to deploy and maintain, and does not require
any other external service (like a database).

It has no admin panel by choice and the only way to dynamically alter its configuration
is by updating the configuration file or use ingress resource annotations.
