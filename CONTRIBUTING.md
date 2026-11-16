# Repository conventions

This repository is **public**: anything pushed must be considered published
forever, history included.

Everything in the repository is written in English: code, comments,
documentation, commit messages, identifiers and result labels.

## Getting started

```bash
make setup   # install the pre-commit hooks (gitleaks)
make help    # list the targets
make lint    # static checks
make test    # Python unit tests (see README.md for the virtual environment)
```

## What never goes into Git

Not in a file, not in a commit message, not in a result:

- AWS account ID, ARNs, resource identifiers, name of the state bucket;
- personal IP address and any `allowed_cidrs` value;
- personal domain name, hostnames of live entry points (ALB, CloudFront,
  API Gateway);
- the `X-Lab-Key` key, Keycloak passwords, private keys and certificates of
  the bench;
- `terraform.tfvars`, `backend.hcl`, state files, `.terraform` directories,
  `terraform output` dumps;
- raw logs from the intermediaries and the instance.

Safeguards in place: `.gitignore`, pre-commit with gitleaks (rules in
`.gitleaks.toml`), the same scan in CI, and `make secrets-scan` to run over
all commits before every push.

If a secret is pushed by mistake, it must be **revoked**. Rewriting history is
not enough.

## Measurement rules

1. **Never modify a `default/` profile** of an intermediary to make a test
   pass. It contains no limit directive. A test that fails with the default
   configuration is a result.
2. In a `mitigated/` profile, every modified directive carries a comment with
   the reason and the original default value.
3. **Every numeric limit** in code, configuration or documentation carries
   either a bench measurement or a source reference (document, section, date
   accessed). No value quoted from memory.
4. `bench/sizes.yaml` is the single source of truth for signature and key
   sizes. No size is hard-coded anywhere else.
5. Container images are pinned by digest; GitHub Actions by commit SHA.
6. Versioned results are sanitised: stable aliases instead of real hostnames,
   no IP address, no account ID.

## Transport

Every exposed listener uses HTTPS. Signing keys and certificates of the bench
are generated at startup and never stored in the repository. A test fixture
that needs a fixed key uses one explicitly marked as a worthless test key.

## Infrastructure

- `terraform apply` and `terraform destroy` only run after the plan and the
  cost estimate have been reviewed.
- Every billable component has its `enable_*` switch, `false` by default. No
  NAT gateway, no SSH, never open the origin to `0.0.0.0/0`.
- Closed scope: no Kubernetes, no managed database.

## Commits

One commit per coherent step, with a descriptive message. The commit address
is the author's GitHub noreply address.

## Third-party licenses

Only include original code and configuration, or material under an
Apache-2.0 compatible license, and credit the origin of any borrowed excerpt.
