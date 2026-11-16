# Payload profiles

One YAML file per token payload profile. The emitter renders a profile into a
JWT claims set, then signs it for the requested variant and header variant.

| Field | Meaning |
| :-- | :-- |
| `name` | Profile identifier, equal to the file name without extension |
| `description` | What the profile represents |
| `source` | Specification the claim set follows |
| `header.typ` | Value of the JWS `typ` header parameter |
| `header.embed_jwk` | `true` when the specification requires the public key in the `jwk` header parameter, whatever the header variant |
| `claims` | Static claims, copied as they are |
| `dynamic` | Claims computed at issuance: `issuer`, `now`, `now+<seconds>`, `uuid`, `random:<bytes>` (base64url of that many random bytes) |

All names, identifiers and group names are fictitious.
