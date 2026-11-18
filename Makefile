# Local developer shortcuts. TEST_DATABASE_URL / TEST_REDIS_URL point tests at running
# services; leave them unset to let Testcontainers start PostgreSQL and Redis in Docker.
.PHONY: install up down migrate seed run test cov lint fmt types security openapi fuzz load

install:   ; uv sync --dev && uv run pre-commit install
up:        ; docker compose up --build -d
down:      ; docker compose down -v
migrate:   ; uv run alembic upgrade head
seed:      ; uv run python -m app.cli seed
run:       ; uv run uvicorn --factory app.main:create_app --reload
test:      ; uv run pytest
cov:       ; uv run pytest --cov=app --cov-report=term-missing --cov-fail-under=80
lint:      ; uv run ruff check . && uv run ruff format --check .
fmt:       ; uv run ruff check --fix . && uv run ruff format .
types:     ; uv run mypy app
security:  ; uv run bandit -c pyproject.toml -r app --severity-level medium && uv export --no-dev --no-hashes --no-emit-project -o /tmp/req.txt && uv run pip-audit -r /tmp/req.txt --strict
openapi:   ; uv run python scripts/export_openapi.py
fuzz:      ; uv run schemathesis run http://localhost:8000/openapi.json --checks all --max-examples 50
load:      ; uv run locust -f load/locustfile.py --host http://localhost:8000
