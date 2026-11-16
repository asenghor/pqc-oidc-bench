# harness

Campaign driver. It sends each token through a chain of intermediaries on a
given channel, compares what the echo backend received with what was sent,
and records a verdict and the component it is attributed to.

```bash
docker compose -f compose/docker-compose.yml --profile tools run --rm harness <command>
```

| Command | Role |
| :-- | :-- |
| `wait` | Wait until the emitter, the echo backend and every intermediary answer |
| `smoke` | Acceptance scenarios of the local bench, then the matrix (`make smoke`) |
| `run` | The matrix only |
| `threshold --chain nginx --channel authorization --http 1.1` | Bisect the largest size a chain accepts on a channel |

## Matrix

[`bench/matrix.yaml`](../../bench/matrix.yaml) declares the axes; the harness
runs their Cartesian product: variant, payload profile, header variant,
channel, chain, HTTP version.

| Channel | Where the token travels |
| :-- | :-- |
| `authorization` | `Authorization: Bearer <token>` |
| `dpop` | `Authorization: DPoP <token>` and `DPoP: <proof>` |
| `cookie` | `Cookie: session=<token>` |
| `query` | `GET /bench?id_token_hint=<token>` |
| `form_post` | `POST` body `id_token=<token>` |

The HTTP version is the one the harness asks for on its own connection. With
`2` it offers both protocols; a component without HTTP/2 answers in HTTP/1.1
and the version actually used is recorded.

Over HTTP/2 the harness sends header values as raw literals, without Huffman
coding. The HPACK encoder of the client library takes quadratic time on
large values, which would make megabyte-sized probes last for minutes. Raw
literals are valid HPACK (RFC 7541, Section 5.2) and decode to the same
value; only the size of the HEADERS frame on the wire differs from what a
client using Huffman coding would send.

## Verdicts

| Verdict | Meaning |
| :-- | :-- |
| `ok` | The echo backend received exactly what was sent |
| `silent_degradation` | No error was reported, but what arrived differs: a header truncated, dropped, split or altered, a changed target or body |
| `explicit_reject` | An HTTP error attributed to a component, or a connection closed without any HTTP response |
| `upstream_error` | A gateway failure: 502, 503 or 504, or a 5xx reported on behalf of a hop that left no tag |

## Attribution

The harness walks the chain from the entry point and reads the `X-Hop-*`
response headers (see [`compose/README.md`](../../compose/README.md)):

- `origin`: this component produced the response (`tagged`);
- no header: this component is at fault but left no tag (`untagged`). Either
  it produced an untagged response that the previous hop relayed, or it gave
  no HTTP answer and the previous hop reported the failure with a status of
  its own;
- `proxied`: the response comes from further down, move to the next hop.

`attributed_to` is therefore the component at fault, which is not always the
one that wrote the status line: when an intermediary resets an HTTP/2 stream,
the hop in front of it answers 500 and the row reads `upstream_error`,
attributed to the intermediary that reset.

The smoke test checks this against a measured reference: each intermediary
is probed alone with a 64 kB header, then every ordered pair must be
attributed to the first of the two that refused alone.

## Results

A run writes `<date>-<id>/` under `RESULTS_DIR`:

| File | Content |
| :-- | :-- |
| `results.csv` | One row per cell: sizes sent, status, HTTP version, hop headers, attribution, verdict, detail, latency |
| `versions.json` | Commit, client libraries, pinned image of each component |
| `matrix.yaml` | Copy of the matrix used |

Rows hold component names, sizes, statuses and verdicts only: no token, no
key, no hostname. `make smoke` writes under `results/_local/`, which is not
versioned.

## Configuration

| Variable | Meaning | Default |
| :-- | :-- | :-- |
| `CERTS_DIR` | Directory holding `ca.crt` and `lab-key` | `/certs` |
| `MATRIX_FILE` | Matrix to run | `/bench/matrix.yaml` in the image |
| `RESULTS_DIR` | Where runs are written | `results/_local` |
| `HARNESS_TARGET_<NAME>` | Base URL of a component, instead of `https://<name>:8443` | unset |
| `COMPOSE_FILE_PATH`, `GIT_COMMIT` | Sources of `versions.json` | set by Compose and the Makefile |
