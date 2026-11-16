# Single entry points for the bench. `make help` lists every target.
SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE_FILE := compose/docker-compose.yml
COMPOSE      := docker compose -f $(COMPOSE_FILE) --profile tools

# The harness writes its results as the invoking user.
export HOST_UID   := $(shell id -u)
export HOST_GID   := $(shell id -g)
export GIT_COMMIT := $(shell git rev-parse HEAD 2>/dev/null)
TF_ENV       := terraform/envs/lab
TF_BOOTSTRAP := terraform/bootstrap

.PHONY: help setup lint test secrets-scan local-up local-down smoke campaign report \
        aws-bootstrap aws-plan aws-apply aws-destroy

# Internal helper: fails explicitly until the phase is delivered.
define not_yet
	@echo "Target '$@' is not available yet: delivered in $(1). See the Status section of README.md." >&2; exit 1
endef

help: ## List the available targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

setup: ## Install the pre-commit hooks (secret detection)
	pre-commit install

lint: ## Run every static check available on this machine
	pre-commit run --all-files
	@if find terraform -name '*.tf' 2>/dev/null | grep -q .; then \
		terraform fmt -check -recursive terraform; \
	else echo "terraform fmt: no .tf file, step skipped"; fi
	@if command -v yamllint > /dev/null; then yamllint .; else echo "yamllint not installed locally: run by CI"; fi
	@if [ -f $(COMPOSE_FILE) ]; then docker compose -f $(COMPOSE_FILE) config --quiet; \
	else echo "docker compose config: no stack yet, step skipped"; fi

test: ## Run the Python unit tests (needs requirements-dev.txt and the service requirements)
	python -m pytest

secrets-scan: ## Scan the whole Git history with gitleaks (run before every push)
	gitleaks git --config .gitleaks.toml --redact --verbose .

local-up: ## Start the local stack over HTTPS and wait until it answers
	@mkdir -p results/_local
	$(COMPOSE) up -d --build --remove-orphans certs emitter echo nginx apache haproxy envoy traefik
	$(COMPOSE) run --rm --build harness wait

local-down: ## Stop the local stack and discard its volume (certificates, lab key)
	$(COMPOSE) down --volumes --remove-orphans

smoke: ## Smoke test against the local stack: acceptance scenarios, then the reduced matrix
	@mkdir -p results/_local
	$(COMPOSE) run --rm --build harness smoke

campaign: ## Run the full matrix and write results/<date>-<id>/ (phase 6)
	$(call not_yet,phase 6)

report: ## Generate the Markdown tables from the results (phase 6)
	$(call not_yet,phase 6)

aws-bootstrap: ## Create the Terraform state bucket (phase 2)
	$(call not_yet,phase 2)

aws-plan: ## Show the Terraform plan and the monthly cost estimate (phase 2)
	$(call not_yet,phase 2)

aws-apply: ## Apply the plan, after explicit confirmation (phase 2)
	$(call not_yet,phase 2)

aws-destroy: ## Destroy the whole infrastructure, after explicit confirmation (phase 2)
	$(call not_yet,phase 2)
