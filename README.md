# VulnTrack — Vulnerability Remediation API

[![Build and Test](https://github.com/Nikkilodeonee/vulntrack/actions/workflows/build.yml/badge.svg)](https://github.com/Nikkilodeon/vulntrack/actions/workflows/build.yml)

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
- **GitHub Actions** CI
- **MockMvc** and **Testcontainers** tests
- **OpenAPI / Swagger UI** documentation (enabled only on the `local` profile)

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
| GET | `/api/findings` | List findings (filter by severity/status) |
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
| GET | `/swagger-ui.html` | Swagger UI (local profile only) |
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
| 400 | `BAD_REQUEST` | Validation failure or invalid workflow transition |
| 401 | `UNAUTHORIZED` | Missing or invalid JWT |
| 403 | `FORBIDDEN` | Role not allowed for action |
| 404 | `NOT_FOUND` | Resource not found |

## Getting started

### Prerequisites

- JDK 17+
- Docker (optional, for Compose and Testcontainers)

### Run with Docker Compose

```bash
docker compose up --build
```

- API: http://localhost:8081
- Swagger UI: http://localhost:8081/swagger-ui.html
- PostgreSQL: localhost:5433

### Run locally (recommended)

**Option A — Docker (easiest, includes PostgreSQL):**

```bash
docker compose up --build
```

API: http://localhost:8081/swagger-ui.html

**Option B — Maven + PostgreSQL:**

You need PostgreSQL running with database `vulntrack` / user `vulntrack` / password `vulntrack`.

```powershell
.\mvnw install -DskipTests
java -jar web\target\web-1.0-SNAPSHOT.jar
```

API: http://localhost:8080/swagger-ui.html

> **Note:** In this multi-module project, use `install` then `java -jar` (or Docker).  
> `spring-boot:run -pl web` alone fails because sibling modules are not in your local Maven cache yet.  
> `spring-boot:run -pl web -am` can also fail on the parent POM — the `java -jar` approach above is the most reliable.

### Build and test

```bash
./mvnw verify
```

- **MockMvc** tests use H2 with the `test` profile
- **Testcontainers** PostgreSQL tests run when Docker is available

## Demo accounts

Passwords are for local development only. Stored as BCrypt hashes; use plain-text values with login API.

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
- Duplicate findings are detected by asset + CVE
- Overdue findings are automatically escalated
- Accepted risk requires reason and expiration date
- Inactive assets cannot receive new findings

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

**Roman Sushkin** — [GitHub](https://github.com/roman-sushkin)
