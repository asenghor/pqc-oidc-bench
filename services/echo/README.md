# echo

Witness backend placed behind every chain of intermediaries. For each request
it reports what actually arrived, so the harness can compare it with what was
sent. A difference without an error status is a silent degradation.

The service only listens over HTTPS: it refuses to start without
`TLS_CERT_FILE` and `TLS_KEY_FILE`.

## Report

Any method and any path answer with a JSON document:

| Field | Content |
| :-- | :-- |
| `request_line` | Length and SHA-256 of `METHOD target HTTP/version`, rebuilt from what the server parsed |
| `target` | Length and SHA-256 of the request target (path and query string) |
| `body` | Length and SHA-256 of the body |
| `watched_headers` | For `authorization`, `dpop` and `cookie`: number of occurrences, length and SHA-256 of each value |
| `headers` | Name and value length of every received header, in order |
| `request_id` | Propagated `X-Request-Id`, or `-` |
| `lab_key_length` | Fixed length of `X-Lab-Key`, to be counted in request sizes |

Every response carries `X-Hop-Echo: 1`.

No header value, target or body is echoed back or logged. The log line of a
request holds the request identifier, the method, the status and lengths. The
access log of the server is disabled, since a request line can carry a token.

## Shared key

Every request except `GET /healthz` must carry `X-Lab-Key`, the shared key of
the bench, exactly 64 characters long. Otherwise the answer is `401`. The key
is read from the file named by `LAB_KEY_FILE`, else from `LAB_KEY`; the
service refuses to start if its length is not 64.

## Request size

The witness must never be the component that rejects. The HTTP/1.1 parser is
therefore given a request head limit of 16 MiB, far above what any
intermediary accepts. This value is a bench setting. The limit that the
witness itself imposes is measured through the direct path of the harness.

## Build

The build context is the repository root:

```bash
docker build -f services/echo/Dockerfile .
```
