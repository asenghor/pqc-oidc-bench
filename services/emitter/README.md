# emitter

Issues the tokens the bench sends through the transport chain. It depends on
no post-quantum signature implementation: every token is a genuine ES256 or
RS256 JWS, which relying parties can verify.

Signing keys and certificates are generated in memory at startup and are lost
when the process stops. The service only listens over HTTPS: it refuses to
start without `TLS_CERT_FILE` and `TLS_KEY_FILE`, which the Compose stack
provides.

## Endpoints

| Endpoint | Role |
| :-- | :-- |
| `POST /token` | One token for a variant, a payload profile and a header variant |
| `GET /jwks` | JWK Set with a chosen number of keys per variant and a chosen `Cache-Control` |
| `POST /introspect` | Token introspection (RFC 7662) for reference tokens |
| `POST /par` | Minimal pushed authorization request endpoint (RFC 9126) |
| `GET /healthz` | Liveness |

`POST /token` and the other `POST` endpoints accept a form-encoded body or a
JSON object.

### POST /token

| Parameter | Values | Default |
| :-- | :-- | :-- |
| `variant` | a `name` of [`bench/sizes.yaml`](../../bench/sizes.yaml) | required for `format=jws` |
| `profile` | a file name of [`bench/profiles/`](../../bench/profiles/) | required |
| `header` | `kid`, `jwk`, `x5c` | `kid` |
| `carrier` | `ES256`, `RS256` (non-classical variants only) | `ES256` |
| `format` | `jws`, `reference` | `jws` |
| `mode` | `calibrated` | `calibrated` |

`mode=real` (real ML-DSA signatures) is disabled and not implemented: the
endpoint answers `501`.

`format=reference` returns an opaque token whose claims are only available
through `POST /introspect`.

The response gives the token and its accounting: `length`, `target_length`,
`padding_bytes`, `signed_with`, `calibrated`.

### GET /jwks

- `keys=ES256:1,ML-DSA-65:2` sets the number of keys per variant. This is how
  a simple rotation, an overlapping rotation and a hybrid fleet are
  simulated. Default: `JWKS_KEYS`, else `ES256:1,RS256:1`.
- `cache_control=public, max-age=300` sets the `Cache-Control` response
  header. Default: `JWKS_CACHE_CONTROL`, else no header.

The first key of `ES256` and `RS256` is the active signing key. Keys of the
other variants are AKP keys (RFC 9964, Section 3) whose `pub` is random bytes
of the exact public key size: they give the document its real size and
cannot verify anything. The same request always returns the same document
for the lifetime of the process.

### POST /introspect

Requires HTTP Basic client authentication (`INTROSPECTION_CLIENT_ID`,
`INTROSPECTION_CLIENT_SECRET`). Without a configured secret a random one is
drawn at startup and the endpoint stays closed. Only reference tokens issued
by this process are active.

### POST /par

Stores the pushed parameters and returns `request_uri` and `expires_in` with
status `201`. Public clients only: `client_id` is required, no client
authentication.

## Calibrated mode

Classical variants (`ES256`, `RS256`) are emitted natively. For any other
variant the emitter signs with the carrier and adds a `pad` claim so that the
compact serialization has, to the byte, the length of the equivalent token in
the targeted variant.

The equivalent token is defined as:

- the same payload, without `pad`;
- a signature of the size given by `sizes.yaml`;
- a protected header with `alg` (the variant's JWS algorithm name), `typ`
  (from the profile), then:
  - `kid`: a JWK SHA-256 thumbprint;
  - `jwk`: an AKP public key, `{"kty":"AKP","alg":…,"pub":…}`, with a `pub`
    of the public key size given by `sizes.yaml`;
  - `x5c`: one self-signed certificate.

  The DPoP profile always embeds `jwk`, as RFC 9449 requires; the header
  variant then adds `kid` or `x5c` to it.

A unit test builds that equivalent token independently for every variant,
profile, header variant and carrier, and checks the equality of lengths.

### Details worth knowing

- **One extra header parameter, sometimes.** An unpadded base64url string
  never has a length of 1 modulo 4, so one total length out of four cannot be
  reached by padding the payload alone. In that case the header receives
  `"pad":"x"`, which moves its encoded length to another residue. Verifiers
  ignore header parameters they do not understand (RFC 7515, Section 4).
- **Padding content.** The padding is random base64url text, not a repeated
  character, so that it compresses like a signature would. It still carries
  less entropy per transmitted byte than a real signature, because it is
  JSON text encoded a second time. This has no effect on a length limit; it
  can matter where compressed size is what counts (HPACK, QPACK).
- **Variable-length signatures.** For composite variants with an ECDSA
  component, `sizes.yaml` holds the maximum signature size and the token is
  calibrated on it.
- **The `x5c` target is a model.** For non-classical variants the certificate
  is a minimal X.509 v3 structure (RFC 5280, Section 4.1) with a short name,
  no extension and a placeholder algorithm identifier, carrying a key and a
  signature of the right sizes. A real certificate is a little larger and
  usually travels with its chain. The `kid` and `jwk` variants have no such
  approximation.

## Configuration

| Variable | Meaning | Default |
| :-- | :-- | :-- |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Server certificate and key | required |
| `LISTEN_HOST`, `LISTEN_PORT` | Listener | `0.0.0.0`, `8443` |
| `EMITTER_ISSUER` | `iss` claim | `https://emitter.bench.test` |
| `BENCH_DIR` | Directory holding `sizes.yaml` and `profiles/` | `bench/` of the repository |
| `JWKS_KEYS`, `JWKS_CACHE_CONTROL` | Defaults of `GET /jwks` | see above |
| `INTROSPECTION_CLIENT_ID`, `INTROSPECTION_CLIENT_SECRET` | Introspection client | see above |

## Build

The build context is the repository root:

```bash
docker build -f services/emitter/Dockerfile .
```
