# Security

## Scope

`pqc-oidc-bench` is a **measurement tool**, not a service. It is not designed
to be exposed or operated in production.

- The intermediaries (nginx, Apache httpd, HAProxy, Envoy, Traefik)
  **deliberately run with their default configuration**, without hardening:
  that is the object of the measurement. The lack of hardening is not a
  vulnerability of the bench.
- The emitter produces size-calibrated tokens, signed with ephemeral keys
  generated at startup. These tokens carry no authentication value outside
  the bench.
- Local TLS certificates are issued by an ephemeral authority, generated at
  startup and never versioned.
- No live entry point, account ID or secret is published in this repository.

## What is worth reporting

- a secret, account ID, IP address or live hostname present in the repository
  or its history;
- a defect of the bench that would expose the workstation or the cloud
  account of whoever reproduces it (for example a network rule more open than
  documented);
- a flaw in the continuous integration chain of the repository.

## Reporting channel

Use GitHub private vulnerability reporting: the **Security** tab of the
repository, then **Report a vulnerability**. Do not open a public issue for an
exposed secret.
