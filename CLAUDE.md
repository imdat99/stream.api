# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Quick Commands

```bash
# Run server
go run ./cmd/server

# Build server
go build ./cmd/server

# Run all tests
go test ./...

# Run service/middleware tests only
go test ./internal/service/... ./internal/middleware/...

# Regenerate GORM models and queries (after DB schema changes)
go run ./cmd/gendb

# Lint protobufs
buf lint

# Generate protobuf code (Go + TypeScript)
buf generate

# Run DB migrations
./run_migration.sh
```

## Architecture Overview

**Module**: `stream.api` (Go 1.25.6)

This is a **gRPC-first backend** for a video streaming platform with agent/render orchestration.

### Layer Structure

```
cmd/              → Entrypoints (server, gendb, worker stub)
internal/
  transport/grpc  → gRPC server, agent runtime, streaming, auth
  service         → Business logic, composed via appServices struct
  repository      → Database access layer (transactions, GORM abstraction)
  database/
    model/        → Generated GORM models (*.gen.go)
    query/        → Generated GORM query builders (*.gen.go)
  adapters/redis  → Redis queue, pub/sub for jobs/agents
  middleware      → gRPC metadata-based internal auth
  dto             → Data transfer objects
  api/proto       → Generated protobuf Go code
proto/            → Source .proto files (app/v1, agent/v1)
pkg/              → Shared utilities (database, logger, storage, auth)
```

### Key Patterns

- **Service composition**: `internal/service/service_core.go` defines `appServices` struct holding all dependencies; typed services (`authAppService`, `paymentsAppService`, etc.) embed it
- **Repository abstraction**: Services depend on repository interfaces, not raw GORM
- **Generated DB layer**: `cmd/gendb/main.go` reads schema and generates models/queries
- **Internal auth**: gRPC metadata (`x-stream-internal-auth`, `x-stream-actor-*`) for service-to-service auth
- **Transaction boundaries**: Repositories handle transactions for multi-entity operations (payments, account deletion, subscription updates)
- **Job/render subsystem**: Jobs in DB + Redis sorted set queue + pub/sub for logs/cancels/updates + MQTT for agent events

### Test Patterns

- In-memory SQLite for service tests (`internal/service/__test__/testdb_setup_test.go`)
- bufconn for gRPC test servers
- Tests isolated and fast, no external Postgres required

## Important Caveats

- **Stale paths in docs/scripts**: `MIGRATION_GUIDE.md` and some scripts reference `cmd/api` or `cmd/grpc` — the actual entrypoint is `cmd/server`
- **Dockerfile**: References `./cmd/grpc` which doesn't exist; likely needs updating to `./cmd/server`
- **Proto path mismatch**: `proto/app/v1/admin.proto` declares `go_package` as `internal/gen/proto/...` but generated code lands in `internal/api/proto/...`

## Notification Settings

- Email: disabled
- Notifications: disabled
