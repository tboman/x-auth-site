.PHONY: all build test tidy run-persona run-pool run-broker run-grant docker-persona docker-pool docker-broker docker-grant

SERVICES := persona pool broker grant transaction risk authentication authenticator

all: build

build:
	@mkdir -p bin
	@for svc in $(SERVICES); do \
		echo ">> building $$svc-service"; \
		go build -o bin/$$svc-service ./services/$$svc-service/cmd || exit 1; \
	done

test:
	go test ./...

tidy:
	go mod tidy

# Local run — each service defaults to its documented port.
run-persona:
	PORT=8180 SERVICE_NAME=persona-service go run ./services/persona-service/cmd

run-pool:
	PORT=8181 SERVICE_NAME=pool-service go run ./services/pool-service/cmd

run-broker:
	PORT=8182 SERVICE_NAME=broker-service \
		PERSONA_SERVICE_URL=http://localhost:8180 \
		POOL_SERVICE_URL=http://localhost:8181 \
		GRANT_SERVICE_URL=http://localhost:8183 \
		go run ./services/broker-service/cmd

run-grant:
	PORT=8183 SERVICE_NAME=grant-service go run ./services/grant-service/cmd

# ── Product 1 services (X-Auth for Apps) ──

run-transaction:
	PORT=8080 SERVICE_NAME=transaction-service \
		RISK_SERVICE_URL=http://localhost:8081 \
		AUTHENTICATION_SERVICE_URL=http://localhost:8082 \
		AUTHENTICATOR_SERVICE_URL=http://localhost:8083 \
		go run ./services/transaction-service/cmd

run-risk:
	PORT=8081 SERVICE_NAME=risk-service go run ./services/risk-service/cmd

run-authentication:
	PORT=8082 SERVICE_NAME=authentication-service \
		AUTHENTICATOR_SERVICE_URL=http://localhost:8083 \
		go run ./services/authentication-service/cmd

run-authenticator:
	PORT=8083 SERVICE_NAME=authenticator-service go run ./services/authenticator-service/cmd

# Build docker images (each service has its own Dockerfile, shared build context at repo root).
docker-%:
	docker build -t x-auth-$*-service -f services/$*-service/Dockerfile .
