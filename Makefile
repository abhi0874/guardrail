.PHONY: install test lint typecheck format-check check
install:
	uv sync --frozen --python 3.11

test:
	uv run --frozen pytest -q

lint:
	uv run --frozen ruff check .

typecheck:
	uv run --frozen mypy src tests

format-check:
	uv run --frozen ruff format --check .

check: lint format-check typecheck test
