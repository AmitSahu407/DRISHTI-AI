# Dhristi AI Backend

FastAPI backend and integrated web dashboard for a software-only campus safety platform that can connect to existing CCTV systems.

## Included
- SQLAlchemy 2.x models for users, cameras, incidents, alerts, buildings, risk zones, audit logs and refresh tokens.
- JWT access/refresh tokens, password hashing and role-based authorization.
- Dashboard KPIs, camera CRUD, incident CRUD/filtering, analytics, AI insight aggregation, system health and audit log APIs.
- Authenticated WebSocket event stream at `/ws/alerts?token=<access_token>`.
- Single-page Dhristi AI dashboard served by FastAPI at `/`, connected to the REST API and live alert WebSocket. Includes login, overview KPIs, camera inventory, incident status updates, analytics, insights and system health.
- PostgreSQL, Redis service in Docker Compose, Alembic environment and simulated AI detector adapters.

## Run locally
1. Install Python 3.12+ and PostgreSQL.
2. `python -m venv .venv` then activate it.
3. `pip install -r requirements.txt`
4. `cp .env.example .env` and set a strong `SECRET_KEY`, database password and bootstrap admin password.
5. `uvicorn app.main:app --reload`
6. Open `http://localhost:8000` for the integrated dashboard.
7. Open `http://localhost:8000/docs` for the API documentation.

Default local admin login (from the example environment): `admin@dhristi.local` / `ChangeThisPassword123!`. Change this immediately for any shared or deployed environment.

For local PostgreSQL, change `DATABASE_URL` in `.env` to your local database connection.

## Run with Docker
Set `POSTGRES_PASSWORD` in your shell or compose environment, update `.env` so the `DATABASE_URL` password matches, then:
`docker compose up --build`

The first startup creates tables for a quick MVP and seeds a bootstrap administrator plus sample buildings, risk zones and cameras. **Do not use `create_all` as a production migration strategy.** Generate and apply migrations:
`alembic revision --autogenerate -m "initial schema"`
`alembic upgrade head`

## Bootstrap admin
Credentials are read from `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`. Change them before first startup. Public registration always creates a Viewer; elevated roles must be granted through a controlled administrative process.

## API routes
All REST routes use `/api/v1`:
- `POST /auth/register`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `GET /auth/me`
- `GET /dashboard/overview`
- `GET|POST /cameras`, `GET|PUT|DELETE /cameras/{id}`
- `GET|POST /incidents`, `GET|PATCH|DELETE /incidents/{id}`
- `GET /analytics/risk`, `GET /analytics/trends`
- `GET /insights`, `GET /system/health`, `GET /logs`
- `WS /ws/alerts?token=...`

Dashboard: `/`
Swagger UI: `/docs`; OpenAPI JSON: `/openapi.json`.

## WebSocket event
```json
{
  "event": "fall_detection",
  "incident_id": 42,
  "location": "Library Corridor",
  "severity": "critical",
  "confidence": 0.97,
  "timestamp": "2026-10-30T10:15:00+00:00",
  "status": "open"
}
```

## Important production work before deployment
This is a structured MVP foundation, not a certified security product. Before handling real CCTV or personal data:
- Use managed secrets, TLS, strict CORS/host allowlists, strong password policy, MFA and account recovery.
- Move rate limiting to Redis and WebSocket fan-out to Redis Pub/Sub or a message broker. Current in-memory implementations are single-process only.
- Add tests, CI, structured observability, database backups, retention/deletion policies and incident-response procedures.
- Use Alembic migrations in deployment; do not rely on automatic table creation.
- Store RTSP credentials in a secrets vault, encrypt them, restrict network egress, and never expose RTSP URLs to ordinary viewers.
- Run RTSP ingestion and YOLO inference in isolated worker processes with reconnect/backoff, health monitoring and bounded queues.
- Validate model accuracy on representative campus footage, measure false positives/negatives, and require human review for consequential actions.
- Implement actual email/Telegram providers and durable background jobs. The included notification service currently queues dashboard notification rows only.
- Add pagination metadata, tenant/college scoping and explicit authorization policies before multi-college SaaS use.
- Treat detection accuracy and AI engine status as unmeasured/simulated until validated telemetry exists.

## Design notes
The risk score is a transparent heuristic over the last seven days of incident severity counts. Tune it using validated operational data. AI detector functions return simulated payloads and do not inspect video frames yet.
