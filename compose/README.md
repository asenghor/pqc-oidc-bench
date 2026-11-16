# Compose stack

`docker-compose.yml` is the base stack of the bench: the emitter, the echo
witness backend and five reverse proxies. It is the same on a workstation and
on the EC2 instance.

```bash
make local-up     # build, start, wait until every component answers
make smoke        # acceptance scenarios, then the reduced matrix
make local-down   # stop and discard the volume
```

No port is published on the host: the harness runs as a container inside the
network (`docker compose --profile tools run --rm harness <command>`).

## Components

| Service | Role | Image |
| :-- | :-- | :-- |
| `certs` | One-shot: ephemeral certificate authority, server certificates, lab key | built from `compose/ca/` |
| `emitter` | Calibrated tokens, JWKS, introspection, PAR | built from `services/emitter/` |
| `echo` | Witness backend | built from `services/echo/` |
| `nginx`, `apache`, `haproxy`, `envoy`, `traefik` | Intermediaries under test | official images, pinned by digest |
| `harness` | Campaign driver, started on demand (`tools` profile) | built from `services/harness/` |

## TLS

Every listener is HTTPS, and every hop verifies the certificate of the next
one against the bench authority, by name.

When the stack starts, `certs` creates a certificate authority, one server
certificate per component and the shared `X-Lab-Key`, in the `certs` Docker
volume. Nothing is written to the repository. The private key of the
authority is never stored: once the certificates are signed it is dropped.
`make local-down` removes the volume, so the next start draws a new
authority and a new key.

The files of the volume are world-readable inside the stack, because the
components run under different unprivileged users. They are throwaway
material for a measurement bench, not credentials to protect.

## Proxy profiles

`proxies/<name>/default/` holds the minimal TLS reverse proxy configuration
of each intermediary, **without any size, buffer or limit setting**. These
files are never edited to make a test pass: a failure with the default
configuration is a result. Raised limits will live in `proxies/<name>/mitigated/`,
selected with `PROXY_PROFILE`; only `default` exists so far.

Each profile exposes HTTP/1.1 and HTTP/2 on port 8443.

## Addressing and chains

Each intermediary is reached by its service name and forwards to the echo
backend. A path starting with `/via/<name>/` is forwarded to that
intermediary instead, which gives two-hop chains:

| Request | Path taken |
| :-- | :-- |
| `https://echo:8443/bench` | echo, directly |
| `https://nginx:8443/bench` | nginx, echo |
| `https://traefik:8443/via/nginx/bench` | traefik, nginx, echo |

The request target is never rewritten, so the echo backend sees the target
the harness sent. Chains are limited to two intermediaries.

## Hop headers

Rejections are attributed to a component through response headers:

- every intermediary sets `X-Hop-<Name>` to `proxied` on a response it
  relays and to `origin` on a response it produces itself;
- the echo backend sets `X-Hop-Echo`.

Some early rejections leave no header at all: a request refused while it is
being parsed (HAProxy), or before routing (Traefik). The harness handles
that case; see [`services/harness/README.md`](../services/harness/README.md).

## Logs

Access logs hold a timestamp, the propagated `X-Request-Id` and the status,
never a URI or another header value, since both can carry tokens. Error logs
of the proxies may quote a request line; like all raw logs they stay in
Docker and never enter the repository.
