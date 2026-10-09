# Multi-User Taskboard MCP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (```- [ ]```) syntax for tracking.

**Goal:** Turn the single-user SQLite taskboard-mcp into a multi-User service where a read-only website shows a User their Tasks, and ChatGPT manages those Tasks over an authenticated MCP endpoint.

**Architecture:** One FastAPI application is three things at once: a server-rendered website, an OAuth 2.1 authorization server (its own login, consent, token, and registration endpoints), and an MCP resource server over Streamable HTTP at /mcp. Postgres stores Users, Tasks, OAuth clients, authorization codes, and tokens. Every Task row carries the user_id that owns it, and a single tasks module applies that scope so isolation is enforced in one place.

**Tech Stack:** Python 3.11+, FastAPI, Uvicorn, SQLAlchemy 2 + Alembic, psycopg 3, pydantic-settings, argon2-cffi, Starlette SessionMiddleware, Jinja2, a little HTMX, the MCP Python SDK (mcp>=2,<3), Postgres 16, pytest + httpx.

**Spec:** [CONTEXT.md](../../../CONTEXT.md) and [docs/adr/](../../adr/) (decisions 0001 to 0005).

## Global Constraints

- Python 3.11 or newer; Postgres 16.
- Task status values are open and completed, stored and filtered with those exact strings. The old complete/completed translation is gone.
- OAuth scopes are exactly tasks:read and tasks:write (security.SCOPE_READ, security.SCOPE_WRITE).
- Access token lifetime 3600 seconds; refresh token lifetime 2592000 seconds. Both are settings, not literals.
- Raw passwords are never stored; hash with argon2. Raw tokens and authorization codes are never stored; store sha256 hex only.
- Every task query is scoped by user_id. No code path reads or writes a Task without a user_id.
- The website has no route that creates, completes, or deletes a Task.
- Configuration comes only from environment variables read through app.config.get_settings(). No secrets in source.
- Only Streamable HTTP at /mcp; the stdio transport and the say_hello tool are removed.
- New dependencies allowed: fastapi, uvicorn[standard], sqlalchemy>=2, alembic, psycopg[binary], pydantic-settings, argon2-cffi, itsdangerous, jinja2, pytest, httpx. Nothing else.
- Tests run against a real Postgres test database, never SQLite.

## Review Focus

Inputs and failure modes the spec implies but a happy-path test would miss. Each has its test in the task named beside it.

1. A token for User A calling complete_task with User B's task id must fail without touching B's row (Task 12).
2. An access token that has expired or been revoked: /mcp must answer 401 so ChatGPT re-authorizes, not 500 (Tasks 11, 13).
3. An authorization code used twice: the second exchange must fail with invalid_grant (Task 9).
4. ChatGPT sending resource as the /mcp URL rather than the bare base URL must be accepted and resolve to the same audience (Task 9).
5. An email typed with different case or surrounding whitespace must resolve to the same User (Tasks 3, 4).

---

## File Structure

The app is split by responsibility, not by layer.

- app/config.py: settings loaded from the environment.
- app/db.py: engine, session factory, FastAPI session dependency, declarative base.
- app/models.py: User, Task, OAuthClient, AuthorizationCode, Token; status constants.
- app/security.py: argon2 hashing, token minting and hashing, PKCE verification, token issue and resolve; scope constants.
- app/tasks.py: the one place Task reads and writes happen, always scoped by user_id.
- app/oauth.py: discovery metadata, Dynamic Client Registration, /authorize + consent, /token.
- app/mcp_server.py: the MCP server and its three task tools, bound to the authenticated User.
- app/web.py: login and logout, the read-only task list, the connect panel.
- app/main.py: assembles the app: middleware, routers, the /mcp auth wrapper.
- app/seed.py: creates Users from the command line, idempotently.
- app/templates/: base.html, login.html, tasks.html, connect.html, consent.html.
- alembic/ and alembic.ini: migrations.
- tests/: conftest.py (owns every shared fixture; each fixture is added by the task that first needs it), test_config.py, test_models.py, test_seed.py, test_web.py, test_oauth.py, test_mcp.py, test_isolation.py.
- Dockerfile, docker-compose.yml, .env.example, requirements.txt (rewritten), README.md (rewritten).

Deleted: server.py, test_server.py.

---

### Task 1: Project skeleton, settings, and local infrastructure

**Files:**
- Create: requirements.txt, app/__init__.py, app/config.py, app/db.py, .env.example, Dockerfile, docker-compose.yml
- Test: tests/test_config.py

**Interfaces:**
- Produces: Settings with fields database_url, public_base_url, session_secret, access_token_ttl_seconds, refresh_token_ttl_seconds; get_settings() -> Settings (cached); engine, SessionLocal, get_session(); Base.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import pytest
from pydantic import ValidationError
from app.config import Settings

def test_settings_read_from_environment(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/db")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://tasks.example.com/")
    monkeypatch.setenv("SESSION_SECRET", "s3cret")
    s = Settings()
    assert s.database_url.endswith("/db")
    assert s.public_base_url == "https://tasks.example.com"  # trailing slash stripped
    assert s.access_token_ttl_seconds == 3600
    assert s.refresh_token_ttl_seconds == 2592000

def test_settings_require_database_url(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_config.py -v
Expected: FAIL with ModuleNotFoundError: No module named 'app'

- [ ] **Step 3: Implement the skeleton**

requirements.txt:

```
fastapi
uvicorn[standard]
sqlalchemy>=2
alembic
psycopg[binary]
pydantic-settings
argon2-cffi
itsdangerous
jinja2
mcp>=2,<3
pytest
httpx
```

app/config.py: a BaseSettings subclass with the five fields, access_token_ttl_seconds: int = 3600, refresh_token_ttl_seconds: int = 2592000, and a field validator that strips a trailing slash from public_base_url. get_settings() is lru_cache-wrapped and passes _env_file=".env".

app/db.py: Base from sqlalchemy.orm.DeclarativeBase; engine = create_engine(get_settings().database_url, pool_pre_ping=True); SessionLocal = sessionmaker(bind=engine, expire_on_commit=False); get_session() yields a session and closes it in finally.

.env.example lists the five variables with placeholder values.

docker-compose.yml runs db (postgres:16, user/password/database taskboard, healthcheck pg_isready) and app (build: ., port 8000:8000, depends_on db with condition service_healthy, the five env vars, DATABASE_URL pointing at host db).

Dockerfile: python:3.13-slim; install requirements; copy app, alembic, alembic.ini; create and switch to a non-root user; CMD runs alembic upgrade head then uvicorn app.main:app --host 0.0.0.0 --port 8000.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_config.py -v
Expected: PASS (2 passed)

- [ ] **Step 5: Verify local infrastructure, then commit**

Run: docker compose up -d db then docker compose exec db pg_isready -U taskboard
Expected: accepting connections

```bash
git add requirements.txt app .env.example Dockerfile docker-compose.yml tests/test_config.py
git commit -m "feat: add app skeleton, settings, and local Postgres infrastructure"
```

---

### Task 2: Data model, test harness, and initial migration

**Files:**
- Create: app/models.py, alembic.ini, alembic/env.py, alembic/script.py.mako, alembic/versions/0001_initial.py
- Create: tests/conftest.py
- Test: tests/test_models.py

**Interfaces:**
- Consumes: app.db.Base, app.db.SessionLocal.
- Produces: User, Task, OAuthClient, AuthorizationCode, Token; STATUS_OPEN = "open", STATUS_COMPLETED = "completed"; the db_session pytest fixture.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_models.py
import pytest
from sqlalchemy import text
from app.models import Task, User

def test_schema_exists(db_session):
    tables = set(db_session.execute(text(
        "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
    )).scalars())
    assert {"users", "tasks", "oauth_clients",
            "oauth_authorization_codes", "oauth_tokens"} <= tables

def test_task_status_rejects_the_old_value(db_session):
    user = User(email="a@example.com", password_hash="x")
    db_session.add(user)
    db_session.flush()
    db_session.add(Task(user_id=user.id, title="t", status="complete"))
    with pytest.raises(Exception):  # CheckViolation from the status CHECK constraint
        db_session.flush()
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_models.py -v
Expected: FAIL: app.models has no Task

- [ ] **Step 3: Implement models, the test harness, and the migration**

app/models.py defines one class per table, with Uuid primary keys defaulting to uuid4:

- User: id, email (unique, stored lowercased and stripped), password_hash, created_at.
- Task: id, user_id (FK users.id, ondelete CASCADE, not null), title, status with CheckConstraint status IN ('open','completed'), created_at; index on (user_id, created_at).
- OAuthClient: client_id (pk, uuid4 hex), client_name, redirect_uris (JSON list), created_at.
- AuthorizationCode: code_hash (pk), client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, resource, expires_at.
- Token: token_hash (pk), client_id, user_id, scope, resource, kind with CheckConstraint kind IN ('access','refresh'), expires_at, revoked_at (nullable).

tests/conftest.py owns the database lifecycle: a session-scoped fixture that points DATABASE_URL at the test database and runs alembic upgrade head once, and a function-scoped db_session fixture that yields a Session and rolls back and closes after each test. Later tasks add their fixtures to this same file.

alembic/env.py imports Base and app.models, reads DATABASE_URL from the environment, and supports offline and online modes. alembic/versions/0001_initial.py creates the five tables with those constraints and down_revision = None.

- [ ] **Step 4: Run migration and tests**

Run: alembic upgrade head then pytest tests/test_models.py -v
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add app/models.py alembic alembic.ini tests/conftest.py tests/test_models.py
git commit -m "feat: add Postgres models, test harness, and initial migration"
```

---

### Task 3: Password hashing, token helpers, and User seeding

**Files:**
- Create: app/security.py, app/seed.py
- Test: tests/test_seed.py

**Interfaces:**
- Consumes: app.db.SessionLocal, app.models.User.
- Produces: SCOPE_READ = "tasks:read", SCOPE_WRITE = "tasks:write"; hash_password(str) -> str, verify_password(str, str) -> bool, new_token() -> str, token_hash(str) -> str, verify_pkce(verifier, challenge) -> bool, issue_tokens(session, *, user_id, client_id, scope, resource) -> dict[str, str], resolve_access_token(session, raw_token, resource) -> Token | None, normalize_email(str) -> str; seed.seed(session, pairs) -> int, seed.main(argv) -> None.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_seed.py
from app import seed
from app.models import User
from app.security import verify_password, normalize_email

def test_seed_is_idempotent_and_hashes_passwords(db_session):
    pairs = [("Alice@Example.com ", "pw-a"), ("bob@example.com", "pw-b")]
    assert seed.seed(db_session, pairs) == 2
    assert seed.seed(db_session, pairs) == 0  # second run adds nothing
    users = db_session.query(User).all()
    assert {u.email for u in users} == {"alice@example.com", "bob@example.com"}
    alice = db_session.query(User).filter_by(email="alice@example.com").one()
    assert alice.password_hash != "pw-a"
    assert verify_password("pw-a", alice.password_hash)
    assert not verify_password("wrong", alice.password_hash)

def test_normalize_email_trims_and_lowercases():
    assert normalize_email("  A@B.COM ") == "a@b.com"
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_seed.py -v
Expected: FAIL: app.seed missing

- [ ] **Step 3: Implement security helpers and the seed command**

app/security.py: hash_password and verify_password use argon2.PasswordHasher; new_token is secrets.token_urlsafe(32); token_hash is sha256(...).hexdigest(); verify_pkce compares the base64url, unpadded sha256 of the verifier to the challenge in constant time; normalize_email strips and lowercases. issue_tokens mints one access token and one refresh token, stores both as Token rows with hashes, scopes, resource, kind, and expiry from settings, and returns a dict with access_token, refresh_token, token_type "Bearer", and expires_in. resolve_access_token looks a token up by token_hash and returns it only when kind is "access", revoked_at is None, expires_at is in the future, and resource matches (accepting either the configured resource or that value with a /mcp suffix).

app/seed.py exposes main(argv) parsing repeated email password pairs and calling seed(session, pairs); seed inserts only emails that do not already exist and returns the count inserted. Guard the entry point with if __name__ == "__main__".

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_seed.py -v
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add app/security.py app/seed.py tests/test_seed.py
git commit -m "feat: add password hashing, token helpers, and User seeding"
```

---

### Task 4: Website login and session

**Files:**
- Create: app/main.py, app/web.py, app/templates/base.html, app/templates/login.html
- Modify: tests/conftest.py (add client, make_user, sign_in)
- Test: tests/test_web.py

**Interfaces:**
- Consumes: app.security.verify_password, app.db.get_session.
- Produces: web.router (FastAPI APIRouter); web.current_user(request, session) -> User | None; web.require_user(request, session) -> User, which redirects to /login when there is no session.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_web.py
def test_login_rejects_a_wrong_password(client, make_user):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": "a@example.com", "password": "wrong"})
    assert r.status_code == 401

def test_login_is_case_and_space_insensitive_and_preserves_next(client, make_user):
    make_user("a@example.com", "right")
    r = client.post("/login", data={"email": " A@Example.COM ", "password": "right",
                                    "next": "/connect"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/connect"

def test_logout_clears_the_session(client, make_user):
    make_user("a@example.com", "right")
    client.post("/login", data={"email": "a@example.com", "password": "right"})
    client.post("/logout")
    r = client.get("/", follow_redirects=False)
    assert r.headers["location"].startswith("/login")
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_web.py -v
Expected: FAIL: no app.main

- [ ] **Step 3: Implement login, logout, and app assembly**

app/main.py builds app = FastAPI(), adds SessionMiddleware with secret_key from settings, includes web.router and oauth.router, and (from Task 11) mounts /mcp.

app/web.py routes: GET /login renders login.html; POST /login normalizes the email, verifies the password, sets request.session["user_id"], and returns 303 to next or /, or 401 on failure; POST /logout clears the session and redirects to /login. current_user reads user_id from the session and loads the User or returns None; require_user raises HTTPException(303, headers={"Location": "/login?next=<quoted path>"}) when absent.

tests/conftest.py adds: client (httpx TestClient over the app, with a fresh session cookie), make_user(email, password) -> User, and sign_in(email, password) which posts /login and asserts success.

base.html is a minimal HTML shell with a nav and a link to /connect; login.html extends it with the email and password form and a hidden next field.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_web.py -v
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add app/main.py app/web.py app/templates tests/conftest.py tests/test_web.py
git commit -m "feat: add website login, logout, and sessions"
```

---

### Task 5: Read-only task list

**Files:**
- Create: app/tasks.py, app/templates/tasks.html
- Modify: app/web.py
- Test: tests/test_web.py

**Interfaces:**
- Consumes: app.models.Task, STATUS_OPEN, STATUS_COMPLETED.
- Produces: tasks.add_task(session, user_id, title) -> Task; tasks.list_tasks(session, user_id, status=None) -> list[Task]; tasks.complete_task(session, user_id, task_id) -> Task, raising tasks.TaskNotFound.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_web.py (added)
def test_task_list_shows_only_the_signed_in_users_tasks(client, make_user, make_task):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    make_task(a, "mine", "open")
    make_task(b, "theirs", "open")
    client.post("/login", data={"email": "a@example.com", "password": "pw"})
    body = client.get("/").text
    assert "mine" in body and "theirs" not in body

def test_task_list_filters_by_status(client, make_user, make_task):
    a = make_user("a@example.com", "pw")
    make_task(a, "still open", "open")
    make_task(a, "all done", "completed")
    client.post("/login", data={"email": "a@example.com", "password": "pw"})
    body = client.get("/", params={"status": "completed"}).text
    assert "all done" in body and "still open" not in body

def test_task_list_requires_a_session(client):
    r = client.get("/", follow_redirects=False)
    assert r.headers["location"].startswith("/login")
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_web.py -v
Expected: FAIL: / returns 404

- [ ] **Step 3: Implement the tasks module and the list route**

app/tasks.py holds the only Task queries. add_task inserts a Task with status open; list_tasks filters by user_id always and by status when given, ordered by created_at; complete_task loads the Task by id AND user_id, raises TaskNotFound when absent, sets status completed, and returns it. class TaskNotFound(Exception).

app/web.py adds GET / using require_user: validate status against the two constants (ignoring anything else), call tasks.list_tasks, and render tasks.html, a table of title and status plus two filter links (blank and ?status=completed) marked with HTMX hx-get and hx-target so the switch swaps only the table. No form and no button that changes a Task.

tests/conftest.py adds make_task(user, title, status) -> Task.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_web.py -v
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add app/tasks.py app/web.py app/templates/tasks.html tests/conftest.py tests/test_web.py
git commit -m "feat: add read-only task list scoped to the signed-in User"
```

---

### Task 6: OAuth discovery metadata

**Files:**
- Create: app/oauth.py
- Modify: app/main.py
- Test: tests/test_oauth.py

**Interfaces:**
- Consumes: app.config.get_settings, app.security.SCOPE_READ, SCOPE_WRITE.
- Produces: oauth.router; oauth.required_scopes() -> list[str].

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth.py
def test_protected_resource_metadata(client):
    d = client.get("/.well-known/oauth-protected-resource").json()
    assert d["resource"] == "https://tasks.example.com"
    assert d["authorization_servers"] == ["https://tasks.example.com"]
    assert d["scopes_supported"] == ["tasks:read", "tasks:write"]

def test_authorization_server_metadata(client):
    d = client.get("/.well-known/oauth-authorization-server").json()
    assert d["issuer"] == "https://tasks.example.com"
    assert d["authorization_endpoint"].endswith("/authorize")
    assert d["token_endpoint"].endswith("/token")
    assert d["registration_endpoint"].endswith("/register")
    assert d["code_challenge_methods_supported"] == ["S256"]
    assert d["token_endpoint_auth_methods_supported"] == ["none"]
    assert set(d["grant_types_supported"]) == {"authorization_code", "refresh_token"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_oauth.py -v
Expected: FAIL: 404

- [ ] **Step 3: Implement the two metadata documents**

Both routes return JSONResponse built from get_settings().public_base_url, which is simultaneously the issuer, the resource, and the base of every endpoint URL. The authorization-server document also advertises response_types_supported ["code"], scopes_supported from required_scopes(), and offline_access alongside the task scopes so ChatGPT requests a refresh token.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_oauth.py -v
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add app/oauth.py app/main.py tests/test_oauth.py
git commit -m "feat: add OAuth discovery metadata endpoints"
```

---

### Task 7: Dynamic Client Registration

**Files:**
- Modify: app/oauth.py
- Modify: tests/conftest.py (add oauth_client)
- Test: tests/test_oauth.py

**Interfaces:**
- Consumes: app.models.OAuthClient.
- Produces: POST /register returning client_id, client_name, redirect_uris, token_endpoint_auth_method.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth.py (added)
def test_register_creates_a_public_client(client, db_session):
    from app.models import OAuthClient
    r = client.post("/register", json={
        "client_name": "ChatGPT",
        "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
    })
    assert r.status_code == 201
    body = r.json()
    assert body["token_endpoint_auth_method"] == "none"
    assert body["client_id"]
    assert db_session.query(OAuthClient).filter_by(client_id=body["client_id"]).one()

def test_register_rejects_missing_redirect_uris(client):
    assert client.post("/register", json={"client_name": "x"}).status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_oauth.py -v
Expected: FAIL: 404

- [ ] **Step 3: Implement the registration endpoint**

POST /register validates that redirect_uris is a non-empty list of absolute https (or http://localhost) URLs, stores an OAuthClient with client_id = uuid4().hex, and returns 201. Invalid input returns 400 with {"error": "invalid_client_metadata"}.

tests/conftest.py adds oauth_client() which POSTs /register with a ChatGPT redirect URI and returns the client_id.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_oauth.py -v
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add app/oauth.py tests/conftest.py tests/test_oauth.py
git commit -m "feat: add dynamic client registration"
```

---

### Task 8: Authorize, consent, and the signed-in User

**Files:**
- Modify: app/oauth.py
- Create: app/templates/consent.html
- Modify: tests/conftest.py (add seed_user_with_password)
- Test: tests/test_oauth.py

**Interfaces:**
- Consumes: app.models.OAuthClient, AuthorizationCode, app.security.new_token, token_hash, app.web.current_user.
- Produces: GET /authorize, POST /authorize.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth.py (added)
AUTH = {
    "response_type": "code",
    "redirect_uri": "https://chatgpt.com/connector_platform_oauth_redirect",
    "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    "code_challenge_method": "S256",
    "scope": "tasks:read tasks:write",
    "state": "xyz",
    "resource": "https://tasks.example.com",
}

def test_authorize_redirects_to_login_when_signed_out(client, oauth_client):
    r = client.get("/authorize", params={**AUTH, "client_id": oauth_client},
                   follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login?next=")

def test_authorize_renders_consent_then_issues_a_code(client, oauth_client, sign_in):
    sign_in("a@example.com", "pw")
    params = {**AUTH, "client_id": oauth_client}
    assert "tasks:read" in client.get("/authorize", params=params).text
    r = client.post("/authorize", data={**params, "decision": "approve"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith(AUTH["redirect_uri"])
    assert "code=" in r.headers["location"] and "state=xyz" in r.headers["location"]

def test_authorize_rejects_an_unregistered_redirect_uri(client, oauth_client, sign_in):
    sign_in("a@example.com", "pw")
    params = {**AUTH, "client_id": oauth_client, "redirect_uri": "https://evil.example/cb"}
    assert client.get("/authorize", params=params).status_code == 400

def test_deny_returns_access_denied(client, oauth_client, sign_in):
    sign_in("a@example.com", "pw")
    params = {**AUTH, "client_id": oauth_client}
    r = client.post("/authorize", data={**params, "decision": "deny"},
                    follow_redirects=False)
    assert "error=access_denied" in r.headers["location"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_oauth.py -v
Expected: FAIL: 404

- [ ] **Step 3: Implement authorize and consent**

GET /authorize validates that client_id exists, response_type is "code", redirect_uri exactly matches one registered for that client, and code_challenge_method is "S256"; any failure returns 400. When current_user is None it redirects (303) to /login?next=<the full original authorize URL, quoted>. Otherwise it renders consent.html with the client name and requested scopes and hidden fields carrying every authorize parameter.

POST /authorize re-validates the same parameters. On decision "approve" it creates an AuthorizationCode: code = new_token(), stored as token_hash(code), with the client, the signed-in User, redirect URI, scope, challenge, resource, and a 600-second expiry, then redirects (303) to redirect_uri?code=...&state=.... On "deny" it redirects with error=access_denied and the state.

tests/conftest.py's sign_in already covers the login the consent step needs; if Task 8's tests want a User whose password is "pw", they use make_user then sign_in.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_oauth.py -v
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add app/oauth.py app/templates/consent.html tests/test_oauth.py
git commit -m "feat: add authorize endpoint and consent screen"
```

---

### Task 9: Token endpoint, authorization code grant

**Files:**
- Modify: app/oauth.py
- Modify: tests/conftest.py (add authorize_code)
- Test: tests/test_oauth.py

**Interfaces:**
- Consumes: app.security.verify_pkce, issue_tokens, app.models.AuthorizationCode.
- Produces: POST /token with grant_type=authorization_code.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth.py (added)
TOKEN = {
    "grant_type": "authorization_code",
    "redirect_uri": AUTH["redirect_uri"],
    "resource": "https://tasks.example.com",
}

def test_token_exchanges_a_code_for_tokens(client, oauth_client, sign_in, authorize_code):
    sign_in("a@example.com", "pw")
    code, verifier = authorize_code(oauth_client)
    r = client.post("/token", data={**TOKEN, "code": code, "client_id": oauth_client,
                                    "code_verifier": verifier})
    body = r.json()
    assert r.status_code == 200 and body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600 and body["access_token"] and body["refresh_token"]

def test_token_rejects_a_bad_verifier(client, oauth_client, sign_in, authorize_code):
    sign_in("a@example.com", "pw")
    code, _ = authorize_code(oauth_client)
    r = client.post("/token", data={**TOKEN, "code": code, "client_id": oauth_client,
                                    "code_verifier": "wrong"})
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

def test_token_rejects_a_replayed_code(client, oauth_client, sign_in, authorize_code):
    sign_in("a@example.com", "pw")
    code, verifier = authorize_code(oauth_client)
    data = {**TOKEN, "code": code, "client_id": oauth_client, "code_verifier": verifier}
    assert client.post("/token", data=data).status_code == 200
    assert client.post("/token", data=data).status_code == 400

def test_token_accepts_the_mcp_url_as_resource(client, oauth_client, sign_in, authorize_code):
    sign_in("a@example.com", "pw")
    code, verifier = authorize_code(oauth_client, resource="https://tasks.example.com/mcp")
    r = client.post("/token", data={**TOKEN, "code": code, "client_id": oauth_client,
                                    "code_verifier": verifier,
                                    "resource": "https://tasks.example.com/mcp"})
    assert r.status_code == 200
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_oauth.py -v
Expected: FAIL: 404

- [ ] **Step 3: Implement the code grant**

POST /token with grant_type=authorization_code looks the code up by token_hash and rejects, as 400 invalid_grant, when it is missing, expired, already used, when client_id or redirect_uri disagree with the stored row, or when verify_pkce fails. Accept resource equal to the configured resource or that value with a /mcp suffix. On success delete the code (single use) and return issue_tokens(...). A missing or unknown grant_type returns 400 unsupported_grant_type.

tests/conftest.py adds authorize_code(client_id, resource=...) which signs in a seeded user, approves consent, and returns (code, code_verifier) with a verifier freshly generated so the S256 challenge matches.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_oauth.py -v
Expected: PASS (12 passed)

- [ ] **Step 5: Commit**

```bash
git add app/oauth.py tests/conftest.py tests/test_oauth.py
git commit -m "feat: exchange authorization codes for tokens"
```

---

### Task 10: Token endpoint, refresh grant with rotation

**Files:**
- Modify: app/oauth.py
- Modify: tests/conftest.py (add tokens)
- Test: tests/test_oauth.py

**Interfaces:**
- Consumes: app.security.issue_tokens, app.models.Token.
- Produces: POST /token with grant_type=refresh_token; the tokens(client_id) fixture returning a full token response.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oauth.py (added)
def test_refresh_returns_a_new_access_token_and_rotates(client, oauth_client, sign_in, tokens):
    sign_in("a@example.com", "pw")
    refresh = tokens(oauth_client)["refresh_token"]
    r = client.post("/token", data={"grant_type": "refresh_token",
                                    "refresh_token": refresh, "client_id": oauth_client})
    assert r.status_code == 200
    assert r.json()["refresh_token"] != refresh

def test_a_rotated_refresh_token_cannot_be_reused(client, oauth_client, sign_in, tokens):
    sign_in("a@example.com", "pw")
    refresh = tokens(oauth_client)["refresh_token"]
    data = {"grant_type": "refresh_token", "refresh_token": refresh, "client_id": oauth_client}
    client.post("/token", data=data)
    again = client.post("/token", data=data)
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_oauth.py -v
Expected: FAIL: invalid_grant even for a fresh token

- [ ] **Step 3: Implement the refresh grant**

Resolve the presented token by hash; require kind "refresh", not revoked, not expired, and the same client_id. On success set revoked_at on the old row, then issue_tokens(...) for the same user, scope, and resource; otherwise 400 invalid_grant.

tests/conftest.py adds tokens(client_id) which runs the full authorize-to-token exchange and returns the parsed JSON.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_oauth.py -v
Expected: PASS (14 passed)

- [ ] **Step 5: Commit**

```bash
git add app/oauth.py tests/conftest.py tests/test_oauth.py
git commit -m "feat: add refresh token grant with rotation"
```

---

### Task 11: MCP endpoint mounted behind token verification

**Files:**
- Create: app/mcp_server.py
- Modify: app/main.py
- Modify: tests/conftest.py (add mcp_url, bearer, revoke, expire)
- Test: tests/test_mcp.py

**Interfaces:**
- Consumes: app.security.resolve_access_token.
- Produces: mcp_server.build_mcp_server(get_user_id) -> MCPServer; an ASGI wrapper mounted at /mcp.

This task pins the integration the design flagged as risky. Two mechanisms can carry the authenticated identity into tool handlers: a per-request server instance built with the User, or one instance reading a ContextVar set by the wrapper. Prefer the ContextVar, because the SDK's Streamable HTTP keeps session state across requests, so a single instance is safer. Whichever the installed SDK supports, the test is the requirement. Confirm the SDK's ASGI entry point by reading the installed package rather than assuming a name.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mcp.py
def test_mcp_requires_a_token(client, mcp_url):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert r.status_code == 401
    assert "resource_metadata=" in r.headers["www-authenticate"]

def test_mcp_lists_tools_with_a_valid_token(client, mcp_url, bearer):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 200
    names = {t["name"] for t in r.json()["result"]["tools"]}
    assert {"add_task", "list_tasks", "complete_task"} <= names

def test_mcp_rejects_a_revoked_token(client, mcp_url, bearer, revoke):
    revoke(bearer)
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 401

def test_mcp_rejects_an_expired_token(client, mcp_url, bearer, expire):
    expire(bearer)
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_mcp.py -v
Expected: FAIL: /mcp returns 404

- [ ] **Step 3: Implement the wrapper and mount the server**

app/mcp_server.py creates MCPServer("taskboard") and exposes build_mcp_server(get_user_id), registering the three tools with oauth2 security metadata naming the scopes tasks:read and tasks:write. For this task the bodies may return {"user_id": ...} only; Task 12 fills them in.

The /mcp wrapper is a small ASGI callable: read the Authorization Bearer value; call resolve_access_token; on failure return 401 with WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource", scope="tasks:read tasks:write"; on success set the context variable to the token's user_id and delegate to the MCP server's Streamable HTTP ASGI app. Mount it in app/main.py.

tests/conftest.py adds mcp_url ("/mcp"), bearer (a freshly issued access token string for a default User), revoke(token_string) (sets revoked_at on that token), and expire(token_string) (backdates expires_at).

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_mcp.py -v
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add app/mcp_server.py app/main.py tests/conftest.py tests/test_mcp.py
git commit -m "feat: serve MCP over authenticated Streamable HTTP"
```

---

### Task 12: Task tools, scoped and scope-enforced

**Files:**
- Modify: app/mcp_server.py
- Modify: tests/conftest.py (add bearer_for, call_tool)
- Test: tests/test_mcp.py

**Interfaces:**
- Consumes: app.tasks.add_task, list_tasks, complete_task; app.security.resolve_access_token.
- Produces: tool results: add_task(title) -> {"id", "title", "status"}; list_tasks(status?) -> [{"id", "title", "status"}]; complete_task(task_id) -> {"id", "title", "status"}.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_mcp.py (added)
def test_tools_scope_to_the_tokens_user(client, mcp_url, bearer_for, make_user):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    add = call_tool(client, mcp_url, bearer_for(a), "add_task", {"title": "mine"})
    assert add["structuredContent"]["title"] == "mine"
    call_tool(client, mcp_url, bearer_for(b), "add_task", {"title": "theirs"})
    listed = call_tool(client, mcp_url, bearer_for(a), "list_tasks", {})
    assert [t["title"] for t in listed["structuredContent"]["tasks"]] == ["mine"]

def test_a_user_cannot_complete_another_users_task(client, mcp_url, bearer_for, make_user):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    made = call_tool(client, mcp_url, bearer_for(b), "add_task", {"title": "theirs"})
    other_id = made["structuredContent"]["id"]
    result = call_tool(client, mcp_url, bearer_for(a), "complete_task", {"task_id": other_id})
    assert result.get("isError") is True
    still = call_tool(client, mcp_url, bearer_for(b), "list_tasks", {"status": "open"})
    assert [t["id"] for t in still["structuredContent"]["tasks"]] == [other_id]

def test_list_tasks_uses_one_status_vocabulary(client, mcp_url, bearer_for, make_user):
    a = make_user("a@example.com", "pw")
    token = bearer_for(a)
    made = call_tool(client, mcp_url, token, "add_task", {"title": "job"})
    call_tool(client, mcp_url, token, "complete_task",
              {"task_id": made["structuredContent"]["id"]})
    done = call_tool(client, mcp_url, token, "list_tasks", {"status": "completed"})
    assert [t["status"] for t in done["structuredContent"]["tasks"]] == ["completed"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_mcp.py -v
Expected: FAIL: tools return stubs

- [ ] **Step 3: Implement the three tools**

Each tool reads the current User id from the context variable, opens a SessionLocal, and calls app.tasks: add_task with the title, list_tasks with the optional status, complete_task with the id. Catch tasks.TaskNotFound and raise the SDK's ToolError("Task not found: <id>"). Require the scope the tool needs from the resolved token (tasks:read for list_tasks, tasks:write for the others) and raise ToolError when it is missing. Return plain dicts so the SDK serializes structured content.

tests/conftest.py adds bearer_for(user) (an access token for that exact User) and call_tool(client, mcp_url, token, name, arguments) (a JSON-RPC tools/call returning the parsed result).

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_mcp.py -v
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add app/mcp_server.py tests/conftest.py tests/test_mcp.py
git commit -m "feat: add scoped task tools over MCP"
```

---

### Task 13: Connect panel and disconnect

**Files:**
- Modify: app/web.py
- Create: app/templates/connect.html
- Modify: tests/conftest.py (add active_token)
- Test: tests/test_web.py

**Interfaces:**
- Consumes: app.models.Token, app.config.get_settings.
- Produces: GET /connect, POST /connect/disconnect.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_web.py (added)
MCP_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}

def test_connect_shows_the_mcp_url_and_connection_state(client, sign_in, make_user,
                                                        active_token):
    u = make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    assert "https://tasks.example.com/mcp" in client.get("/connect").text
    active_token(u)
    assert "Connected" in client.get("/connect").text

def test_disconnect_revokes_every_token_for_that_user(client, sign_in, make_user,
                                                      bearer_for, mcp_url):
    u = make_user("a@example.com", "pw")
    sign_in("a@example.com", "pw")
    token = bearer_for(u)
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post(mcp_url, json=MCP_LIST, headers=headers).status_code == 200
    client.post("/connect/disconnect")
    assert client.post(mcp_url, json=MCP_LIST, headers=headers).status_code == 401
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_web.py -v
Expected: FAIL: 404

- [ ] **Step 3: Implement the panel and disconnect**

GET /connect uses require_user, computes mcp_url = get_settings().public_base_url + "/mcp", reports connected when the User has an unrevoked, unexpired refresh token, and renders connect.html showing the URL with a copy button and the state.

POST /connect/disconnect sets revoked_at on every token row for the signed-in User and redirects to /connect. Tasks are untouched. The button is an HTMX hx-post targeting the panel, and the page states that connecting is done from ChatGPT's connector settings, with a link to them.

tests/conftest.py adds active_token(user) which issues and stores a live refresh token for that User so the panel reports connected.

- [ ] **Step 4: Run test to verify it passes**

Run: pytest tests/test_web.py -v
Expected: PASS (8 passed)

- [ ] **Step 5: Commit**

```bash
git add app/web.py app/templates/connect.html tests/conftest.py tests/test_web.py
git commit -m "feat: add connect panel and disconnect"
```

---

### Task 14: Cleanup, end-to-end isolation test, and README

**Files:**
- Delete: server.py, test_server.py
- Create: tests/test_isolation.py
- Modify: README.md, tests/conftest.py (add register_connector, connect_user)

- [ ] **Step 1: Write the failing test**

```python
# tests/test_isolation.py
def test_two_users_are_fully_isolated_end_to_end(client, register_connector, connect_user,
                                                 call_tool):
    connector = register_connector()
    a = connect_user("a@example.com", "pw", connector)
    b = connect_user("b@example.com", "pw", connector)
    mine = call_tool(client, a, "add_task", {"title": "a-task"})["structuredContent"]
    call_tool(client, b, "add_task", {"title": "b-task"})
    listed = call_tool(client, a, "list_tasks", {})["structuredContent"]["tasks"]
    assert [t["title"] for t in listed] == ["a-task"]
    blocked = call_tool(client, b, "complete_task", {"task_id": mine["id"]})
    assert blocked.get("isError") is True
    after = call_tool(client, a, "list_tasks", {})["structuredContent"]["tasks"]
    assert [t["status"] for t in after] == ["open"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: pytest tests/test_isolation.py -v
Expected: FAIL: fixtures register_connector, connect_user missing

- [ ] **Step 3: Add the two fixtures, delete the old server, rewrite the README**

tests/conftest.py adds register_connector() (POSTs /register and returns the client_id) and connect_user(email, password, client_id) (signs in, approves consent, exchanges the code, returns the access token).

Delete server.py and test_server.py.

README.md documents the five environment variables; docker compose up for local work; python -m app.seed email password ... to create Users; pointing ChatGPT at the /mcp URL and choosing OAuth; that the website is read-only by design; and that the cluster ingress supplies the public HTTPS URL.

- [ ] **Step 4: Run the whole suite and bring the stack up**

Run: pytest -v then docker compose up --build and open http://localhost:8000/connect
Expected: all tests pass; the app starts, migrates, and serves the login page.

- [ ] **Step 5: Commit**

```bash
git rm server.py test_server.py
git add tests/conftest.py tests/test_isolation.py README.md
git commit -m "test: add end-to-end isolation coverage and refresh docs"
```

