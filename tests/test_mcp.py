import pytest

from app.config import get_settings
from app.models import Token
from app.security import issue_tokens, token_hash


def test_mcp_requires_a_token(client, mcp_url):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    follow_redirects=False)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == (
        f'Bearer resource_metadata="{get_settings().public_base_url}/.well-known/oauth-protected-resource", '
        'scope="tasks:read tasks:write"'
    )


def test_mcp_lists_tools_with_a_valid_token(client, mcp_url, bearer):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"}, follow_redirects=False)
    assert r.status_code == 200
    tools = {t["name"]: t for t in r.json()["result"]["tools"]}
    assert {"add_task", "list_tasks", "complete_task"} == set(tools)
    for name, scope in [("list_tasks", "tasks:read"), ("add_task", "tasks:write"),
                        ("complete_task", "tasks:write")]:
        assert tools[name]["_meta"]["securitySchemes"] == [{"type": "oauth2", "scopes": [scope]}]


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


@pytest.mark.parametrize("authorization", ["Bearer unknown", "Bearer", "Bearer ", "Basic token",
                                            "Bearer token extra"])
def test_mcp_rejects_invalid_authorization(client, mcp_url, authorization):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": authorization})
    assert r.status_code == 401


@pytest.mark.parametrize("change", ["refresh", "wrong-resource"])
def test_mcp_rejects_tokens_not_valid_for_this_resource(client, mcp_url, bearer, db_session, change):
    token = db_session.get(Token, token_hash(bearer))
    if change == "refresh":
        token.kind = "refresh"
    else:
        token.resource = "https://other.example.com"
    db_session.commit()
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 401


@pytest.mark.parametrize("name,arguments", [("list_tasks", {}), ("add_task", {"title": "Task"}),
                                           ("complete_task", {"task_id": "a-task-id"})])
def test_mcp_tools_receive_the_current_tokens_user(
    client, mcp_url, bearer, db_session, make_user, oauth_client, name, arguments,
):
    first_id = db_session.get(Token, token_hash(bearer)).user_id
    second = make_user("other-mcp@example.com", "pw")
    other = issue_tokens(
        db_session, user_id=second.id, client_id=oauth_client,
        scope="tasks:read tasks:write", resource=get_settings().public_base_url + "/mcp",
    )["access_token"]
    db_session.commit()
    for token, user_id in [(bearer, first_id), (other, second.id), (bearer, first_id)]:
        r = client.post(mcp_url, json={
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["result"]["structuredContent"] == {"user_id": str(user_id)}


@pytest.mark.parametrize("method", ["GET", "DELETE"])
def test_mcp_authenticates_all_transport_methods(client, mcp_url, method):
    r = client.request(method, mcp_url, follow_redirects=False)
    assert r.status_code == 401


@pytest.mark.parametrize("invalidate", ["revoke", "expire"])
def test_mcp_rechecks_the_token_on_every_request(client, mcp_url, bearer, revoke, expire, invalidate):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {"Authorization": f"Bearer {bearer}"}
    assert client.post(mcp_url, json=payload, headers=headers).status_code == 200
    {"revoke": revoke, "expire": expire}[invalidate](bearer)
    r = client.post(mcp_url, json=payload, headers=headers)
    assert r.status_code == 401
    assert 'scope="tasks:read tasks:write"' in r.headers["www-authenticate"]


def test_mcp_rejects_duplicate_authorization_headers(client, mcp_url, bearer):
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers=[("Authorization", f"Bearer {bearer}"),
                             ("Authorization", f"Bearer {bearer}")])
    assert r.status_code == 401


def test_mcp_token_lookup_failure_does_not_expose_database_details(client, mcp_url, bearer, monkeypatch):
    from sqlalchemy.exc import SQLAlchemyError

    def fail_lookup(*args):
        raise SQLAlchemyError("private database details")

    monkeypatch.setattr("app.mcp_server.resolve_access_token", fail_lookup)
    r = client.post(mcp_url, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={"Authorization": f"Bearer {bearer}"})
    assert r.status_code == 503
    assert r.json() == {"error": "server_error"}


def test_mcp_supports_the_initialize_handshake(client, mcp_url, bearer, db_session):
    headers = {"Authorization": f"bearer {bearer}", "Accept": "application/json, text/event-stream"}
    r = client.post(mcp_url, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "taskboard-tests", "version": "1.0"},
        },
    }, headers=headers)
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["protocolVersion"] == "2025-11-25"
    assert result["serverInfo"]["name"] == "taskboard"
    assert "tools" in result["capabilities"]
    headers["MCP-Protocol-Version"] = result["protocolVersion"]
    assert client.post(mcp_url, json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                       headers=headers).status_code == 202
    r = client.post(mcp_url, json={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "list_tasks", "arguments": {}},
    }, headers=headers)
    assert r.status_code == 200
    user_id = db_session.get(Token, token_hash(bearer)).user_id
    assert r.json()["result"]["structuredContent"] == {"user_id": str(user_id)}
