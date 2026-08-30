# VulnTrack — Vulnerability Remediation API

[![Build and Test](https://github.com/Nikkilodeonee/vulntrack/actions/workflows/build.yml/badge.svg)](https://github.com/Nikkilodeonee/vulntrack/actions/workflows/build.yml)
[![CodeQL](https://github.com/Nikkilodeonee/vulntrack/actions/workflows/codeql.yml/badge.svg)](https://github.com/Nikkilodeonee/vulntrack/actions/workflows/codeql.yml)

**VulnTrack** is a Spring Boot backend for managing security vulnerabilities across company assets. It supports asset inventory, scan imports, CVSS-based risk scoring, remediation workflows, role-based access control, audit history, accepted-risk handling, SLA deadlines, and automated escalation.

Personal portfolio project — domain inspired by how AppSec teams triage scan results after security assessments.

## Highlights

- Production-style **multi-module** Spring Boot REST API
- **JWT authentication** with role-based access control
- Finding **workflow state machine** with audit history
- **Risk score** = CVSS × asset criticality multiplier
- **SLA deadlines** and hourly **overdue escalation** job
- PostgreSQL + **Flyway** migrations
- **Docker Compose** local environment
- **GitHub Actions** CI with **CodeQL**
- **MockMvc** and **Testcontainers** tests
- **OpenAPI / Swagger UI** documentation (enabled on the `local` and `demo` profiles)

## Demo

```bash
docker compose up --build
```

- API: http://localhost:8081
- Swagger UI: http://localhost:8081/swagger-ui.html
- PostgreSQL: `localhost:5433`

`/` redirects to Swagger. Logins:

| User | Password | Role |
|------|----------|------|
| `admin` | `AdminSecret123` | ADMIN |
| `analyst` | `AnalystSecret123` | SECURITY_ANALYST |
| `engineer` | `EngineerSecret123` | ENGINEER |
| `viewer` | `ViewerSecret123` | VIEWER |

## Architecture

| Module | Responsibility |
|--------|----------------|
| `api` | Shared DTOs and domain enums |
| `persistence` | JPA entities and repositories |
| `service` | Domain-oriented application services |
| `web` | REST controllers, JWT security, Flyway, scheduler |

Application services in `service`:

| Service | Responsibility |
|---------|----------------|
| `AssetService` | Asset create/list |
| `ScanService` | Scan registration |
| `FindingService` | Finding create/query, comments, history |
| `FindingWorkflowService` | Remediation transitions + SLA escalation |
| `DashboardService` | Risk summary aggregations |
| `AuthService` / `JwtTokenService` | Login and JWT |
| `RiskScoringService` | CVSS × criticality scoring |

```
Client → Controller → FindingWorkflowService → Repositories + FindingHistoryWriter
                   ↘ FindingService / AssetService / ScanService / DashboardService
Scheduler ─────────→ FindingWorkflowService (SLA escalation)
Flyway ────────────────────────────────────────────────→ PostgreSQL
```

## Finding workflow

```
DETECTED → CONFIRMED → ASSIGNED → IN_PROGRESS → PATCHED → VERIFIED → CLOSED
```

Alternative exits: `FALSE_POSITIVE`, `ACCEPTED_RISK`, `DUPLICATE`

## Roles

| Role | Capabilities |
|------|--------------|
| `ADMIN` | Full access including asset creation and assignment |
| `SECURITY_ANALYST` | Confirm, verify, close, false positive, accept risk |
| `ENGINEER` | Remediate assigned findings |
| `VIEWER` | Read-only access |

## Risk scoring and SLA

**Risk score** = `CVSS score × asset criticality multiplier`

| Asset criticality | Multiplier |
|-------------------|------------|
| LOW | 1.0 |
| MEDIUM | 1.2 |
| HIGH | 1.5 |
| CRITICAL | 2.0 |

| Risk severity | SLA deadline |
|---------------|--------------|
| CRITICAL | 7 days |
| HIGH | 14 days |
| MEDIUM | 30 days |
| LOW | 90 days |

Overdue findings are marked **escalated** hourly by a scheduled job.

## API endpoints

All `/api/**` endpoints require `Authorization: Bearer <token>` except login.

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/login` | Obtain JWT |
| POST | `/api/assets` | Create asset |
| GET | `/api/assets` | List assets |
| POST | `/api/scans` | Register scan |
| POST | `/api/findings` | Import finding |
| GET | `/api/findings` | List findings (paginated; filter by severity/status) |
| PATCH | `/api/findings/{id}/confirm` | Confirm finding |
| PATCH | `/api/findings/{id}/assign` | Assign engineer |
| PATCH | `/api/findings/{id}/start-progress` | Start remediation |
| PATCH | `/api/findings/{id}/mark-patched` | Mark patched |
| PATCH | `/api/findings/{id}/verify` | Verify fix |
| PATCH | `/api/findings/{id}/close` | Close finding |
| PATCH | `/api/findings/{id}/false-positive` | Mark false positive |
| PATCH | `/api/findings/{id}/accept-risk` | Accept risk |
| GET | `/api/findings/{id}/history` | Audit trail |
| POST | `/api/findings/{id}/comments` | Add comment |
| GET | `/api/dashboard/risk-summary` | Dashboard metrics |
| GET | `/swagger-ui.html` | Swagger UI (`local` and `demo` profiles) |
| GET | `/actuator/health` | Health check |

## Error responses

```json
{
  "error": "BAD_REQUEST",
  "message": "Inactive assets cannot receive new findings."
}
```

| Status | Error | When |
|--------|-------|------|
| 400 | `BAD_REQUEST` | Validation failure, invalid workflow transition, or page size above 100 |
| 401 | `UNAUTHORIZED` | Missing or invalid JWT |
| 403 | `FORBIDDEN` | Role not allowed for action |
| 404 | `NOT_FOUND` | Resource not found |
| 409 | `CONFLICT` | Stale finding update (optimistic lock) or concurrent canonical import for the same asset + CVE |

## Getting started

### Prerequisites

- JDK 17+
- Docker (for Compose and Testcontainers)

### Docker Compose

Same command as [Demo](#demo):

```bash
docker compose up --build
```

### Maven + PostgreSQL

PostgreSQL must be running with database `vulntrack`, user `vulntrack`, password `vulntrack`.

```powershell
.\mvnw install -DskipTests
java -jar web\target\web-1.0-SNAPSHOT.jar
```

API: http://localhost:8080/swagger-ui.html

In this multi-module project, use `install` then `java -jar`. `spring-boot:run -pl web` fails unless sibling modules are already in the local Maven cache.

### Deploy on Railway

1. New project → deploy from `Nikkilodeonee/vulntrack` (Dockerfile).
2. Add PostgreSQL. Railway sets `DATABASE_URL`; the app maps it to JDBC.
3. Set `SPRING_PROFILES_ACTIVE=demo` and `JWT_SECRET` (at least 32 characters; do not reuse the Compose default).

Health check: `/actuator/health`. Root `/` opens Swagger. Demo accounts are the same as above.

### Build and test

```bash
./mvnw verify
```

- **Surefire** (`./mvnw test`): unit tests and H2 MockMvc tests (`test` profile)
- **Failsafe** (part of `verify`): PostgreSQL Testcontainers tests (`*IT`) when Docker is available
- GitHub Actions runs `./mvnw verify` on `ubuntu-latest` (Docker present), so Flyway migrations and Postgres integration tests execute in CI
- A separate **CodeQL** workflow scans Java on push, pull request, and a weekly schedule
- If Docker is not running locally, the Postgres `*IT` classes are skipped rather than failed

## Engineering / Reliability

Finding updates use JPA optimistic locking (`@Version`) so two workflow operations on the same finding cannot silently overwrite each other. The loser is rejected with HTTP `409 Conflict`; the response does not expose Hibernate exception details.

Duplicate detection is still “one canonical finding per asset + CVE”. Re-imports of an existing pair become `DUPLICATE` rows that point at the original. PostgreSQL enforces the canonical side with a partial unique index (`status <> 'DUPLICATE'`), so two concurrent imports cannot both insert `DETECTED`. Sequential re-imports still return `201` with `status=DUPLICATE`; a race that hits the index returns `409`.

SLA, accepted-risk expiry, and overdue escalation use an injected `Clock` (`Clock.systemUTC()` in production) so boundary tests can freeze business time instead of depending on the machine date. A finding is overdue only when `dueDate` is **before** today; due today is not escalated.

`GET /api/findings` is paginated:

| Parameter | Default | Notes |
|-----------|---------|--------|
| `page` | `0` | Zero-based |
| `size` | `20` | Requests larger than **100** are rejected with `400` (not silently clamped) |
| `sort` | `id,asc` | Allowed: `id`, `dueDate`, `createdAt`, `updatedAt`, `severity`, `status`, `cvssScore`, `riskScore`, `cveId`, `title` |
| `severity`, `status` | optional | Existing filters still apply |

Response shape:

```json
{
  "content": [],
  "page": 0,
  "size": 20,
  "totalElements": 0,
  "totalPages": 0,
  "first": true,
  "last": true
}
```

Listing a page of findings loads `asset`, `scan`, `assignedEngineer`, and `duplicateOf` with fetch joins so the mapper does not issue one extra query per row. Measured on PostgreSQL for 20 findings across 20 assets: **22 SQL statements before the fetch-join, 3 after**.

PostgreSQL also checks that `cvss_score` is between 0 and 10, and that an escalated finding has `escalated_at` set. These constraints back the same rules already validated in Java; they are not a second workflow engine.

## Demo accounts

Passwords are for local and Railway demo use. Stored as BCrypt hashes; send the plain-text values to `POST /api/auth/login`.

| User | Password | Role |
|------|----------|------|
| `admin` | `AdminSecret123` | ADMIN |
| `analyst` | `AnalystSecret123` | SECURITY_ANALYST |
| `engineer` | `EngineerSecret123` | ENGINEER |
| `viewer` | `ViewerSecret123` | VIEWER |

### Example: login and list assets

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"analyst","password":"AnalystSecret123"}' | jq -r .token)

curl -s http://localhost:8080/api/assets \
  -H "Authorization: Bearer $TOKEN"
```

## Business rules

- Critical findings receive SLA deadlines when confirmed
- Only security analysts can confirm or mark false positive
- Only the assigned engineer can mark a finding as patched
- A finding cannot be closed unless it was verified
- Every status change creates a history record
- Duplicate findings are detected by asset + CVE (at most one non-`DUPLICATE` row; PostgreSQL enforces this)
- Overdue findings are automatically escalated
- Accepted risk requires reason and expiration date at least one day ahead
- Inactive assets cannot receive new findings
- Concurrent workflow updates on the same finding version fail with `409`

## Tech stack

| Technology | Version |
|------------|---------|
| Java | 17 |
| Spring Boot | 3.4.13 |
| Spring Security + JWT | jjwt 0.12.6 |
| PostgreSQL | 16 |
| Flyway | managed by Spring Boot |
| Testcontainers | 1.20.4 |
| springdoc-openapi | 2.8.6 |

## License

MIT License — see [LICENSE](LICENSE).

## Author

**Roman Sushkin** — [GitHub](https://github.com/Nikkilodeonee)
