.PHONY: rules build up down logs test web-test

rules:
	./scripts/fetch-rules.sh

build:
	./scripts/compose.sh build scanner

up:
	./scripts/compose.sh up --build -d scanner

down:
	./scripts/compose.sh down

logs:
	./scripts/compose.sh logs -f scanner

test:
	cd backend && go test ./...
	cd frontend && npm ci && npm run build

web-test:
	cd frontend && npm ci && npm run build
