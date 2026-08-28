# NEUROTRACE — common workflows.
# Run `make help` for the full list.

SHELL := /bin/bash
IMAGE := neurotrace:2.0
COMPOSE := docker compose

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	    awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build the production image (downloads ISF symbols)
	$(COMPOSE) build app

.PHONY: build-fast
build-fast: ## Build without ISF symbols (faster, smaller image, Vol3 falls back to mock)
	$(COMPOSE) build --build-arg NEUROTRACE_SKIP_SYMBOLS=1 app

.PHONY: up
up: ## Start the app in the background
	$(COMPOSE) up -d app
	@echo "→ Dashboard: http://localhost:8010"
	@echo "→ Health:    http://localhost:8010/api/health"

.PHONY: down
down: ## Stop and remove the containers
	$(COMPOSE) down

.PHONY: logs
logs: ## Tail the app logs
	$(COMPOSE) logs -f app

.PHONY: health
health: ## Hit /api/health from inside the running container
	$(COMPOSE) exec app curl -s http://127.0.0.1:8010/api/health

.PHONY: shell
shell: ## Open a bash shell inside the running container
	$(COMPOSE) exec app bash

.PHONY: test
test: ## Run the full test suite inside the image
	$(COMPOSE) run --rm --no-deps app pytest -ra

.PHONY: test-live
test-live: ## Run the test suite including the live AkashML integration test
	$(COMPOSE) run --rm --no-deps app bash -c "NEUROTRACE_FORCE_LIVE=1 pytest -ra"

.PHONY: analyze
analyze: ## Analyze a memory dump (usage: make analyze FILE=path/to/dump.raw)
	@test -n "$(FILE)" || (echo "usage: make analyze FILE=path/to/dump"; exit 1)
	$(COMPOSE) run --rm app python -m neurotrace.cli analyze "$(FILE)"

.PHONY: velo-health
velo-health: ## Hit Velociraptor health from inside the container
	$(COMPOSE) run --rm app python -m neurotrace.cli health

.PHONY: velo
velo: ## Analyze a Velociraptor client (usage: make velo CLIENT=C.xxxx)
	@test -n "$(CLIENT)" || (echo "usage: make velo CLIENT=C.xxxx"; exit 1)
	$(COMPOSE) run --rm app python -m neurotrace.cli velo "$(CLIENT)"

.PHONY: clean
clean: ## Remove containers, volumes, and the built image
	$(COMPOSE) down -v --remove-orphans
	docker rmi -f $(IMAGE) 2>/dev/null || true
