.PHONY: up down neo4j init-schema load-structured smoke-test pipeline build-indexes eval lint test

# Infrastructure
up:
	docker compose up -d neo4j

up-all:
	docker compose --profile gpu --profile observability up -d

down:
	docker compose --profile gpu --profile observability down

neo4j:
	docker compose up -d neo4j

# Ingestion
init-schema:
	python -m scripts.01_init_schema

load-structured:
	python -m scripts.02_load_structured

smoke-test:
	python -m scripts.smoke_test

pipeline:
	python -m scripts.03_run_pipeline

build-indexes:
	python -m scripts.04_build_indexes

# Query (interactive)
query:
	python -c "from crtkb.query.rag import interactive; interactive()"

# Evaluation
eval:
	python -m scripts.05_run_eval

# Development
lint:
	ruff check src/ scripts/ tests/
	ruff format --check src/ scripts/ tests/

format:
	ruff check --fix src/ scripts/ tests/
	ruff format src/ scripts/ tests/

test:
	pytest tests/ -v

# Full pipeline
ingest: init-schema load-structured smoke-test build-indexes
	@echo "Structured backbone loaded and verified."
