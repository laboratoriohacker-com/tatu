.PHONY: dev dev-backend dev-frontend test lint seed generate-events db migrate build

# Start both backend and frontend
dev:
	docker compose up backend frontend

dev-backend:
	docker compose up backend

dev-frontend:
	docker compose up frontend

test:
	docker compose --profile test run --rm test

lint:
	docker compose --profile lint run --rm frontend-lint

build:
	docker compose --profile build run --rm frontend-build

seed:
	docker compose run --rm backend python -m app.seed

generate-events:
	docker compose run --rm backend python -m app.generate_events $(COUNT) $(HOURS)

db:
	docker compose up -d db

migrate:
	docker compose run --rm backend alembic upgrade head
