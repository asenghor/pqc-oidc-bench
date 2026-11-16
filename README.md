# pqc-oidc-bench

A test bench for the **deployability of post-quantum signatures in
OAuth 2.0 / OpenID Connect**.

Built as part of an Executive MSc in Cybersecurity thesis (Architect track).

## Purpose

Research question: under which conditions can an existing OAuth 2.0 / OIDC
architecture adopt post-quantum or hybrid signatures without breaking
interoperability or regressing operationally?

Hypothesis under test: in OAuth/OIDC, the limits that are hit are hard,
configured limits (cookie, header, request line, gateway). Crossing them
produces a rejection or a silent degradation, not a proportional overhead as
in TLS.

The bench produces two measurements that cannot be derived from a size
calculation:

1. **The failure mode on overflow**, component by component: explicit
   rejection (which HTTP status, emitted by whom) or silent degradation
   (header truncated or dropped, cookie ignored, session lost).
2. **The cost of distributing keys through JWKS during rotations**: document
   size, caching and refresh behaviour of relying parties.

Four migration strategies are compared: ML-DSA alone, hybrid composite
signatures, FN-DSA, and reference tokens with introspection.

### Design principles

- **No dependency on any third-party post-quantum signature
  implementation.** A purpose-built emitter produces classical tokens (RS256
  or ES256) calibrated, to the byte, on the real size of each variant. The
  measurement targets the transport chain and the relying parties.
- **A single Docker Compose stack**, identical on a workstation and on an EC2
  instance. AWS only contributes the managed intermediaries (ALB,
  API Gateway, CloudFront, WAF).
- **HTTPS everywhere.** Every exposed listener uses TLS. Locally, an ephemeral
  certificate authority is generated when the stack starts; it is never
  versioned.
- **Unmodified default configurations.** A test that fails with the default
  configuration is a result, not a defect to fix.

## Status

| Phase | Content | State |
| :-- | :-- | :-- |
| 0 | Preflight: repository, guardrails, CI | done |
| 1 | Local bench: emitter, echo, five intermediaries, harness | to do |
| 2 | AWS foundation: network, compute, budget, bootstrap | to do |
| 3 | Managed intermediaries: ALB, API Gateway, CloudFront, WAF | to do |
| 4 | Relying parties and browsers | to do |
| 5 | Keycloak | to do |
| 6 | Campaign and reporting | to do |
| 7 | Teardown and reproducibility | to do |

No measurement result has been published yet.

## Local reproduction

Prerequisites: Docker with the Compose plugin, GNU Make, Git.

```bash
git clone https://github.com/asenghor/pqc-oidc-bench.git && cd pqc-oidc-bench
make local-up
make smoke
```

These targets ship with phase 1. `make help` lists every target and its state.

## AWS deployment

Coming with phases 2 and 3. Deployment uses Terraform; every billable
component has its own switch, off by default. No live entry point is or will
be published in this repository.

## Known limitations

- The default mode does not produce real post-quantum signatures: it measures
  the effect of token **size**, not the computation cost.
- Out of scope: post-quantum TLS and hybrid key exchange, X.509 certificates
  and mTLS, WebAuthn, SAML, CPU performance of signing and verification, high
  availability, production hardening.

## Prior work

[Arpan0995/pqc-jose-token-limits](https://github.com/Arpan0995/pqc-jose-token-limits)
measured token sizes, the default limits of four embedded Java servers
(Jetty, Tomcat, Undertow, Netty) and HPACK. This bench covers what is
missing: real chained intermediaries, AWS managed components, tokens carried
in a URL, relying parties, browsers, and JWKS under rotation.

## Contributing, security, citation

- Repository conventions and guardrails: [CONTRIBUTING.md](CONTRIBUTING.md)
- Scope and reporting: [SECURITY.md](SECURITY.md)
- To cite this bench: [CITATION.cff](CITATION.cff)

## License

[Apache-2.0](LICENSE)
