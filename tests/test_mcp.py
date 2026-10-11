from uuid import uuid4

import pytest

from app.config import get_settings
from app.models import Token
from app.security import token_hash


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
    assert {
        "add_task", "list_tasks", "complete_task", "delete_task", "update_task",
        "reopen_task", "clear_completed_tasks",
    } == set(tools)
    for name, scope in [("list_tasks", "tasks:read"), ("add_task", "tasks:write"),
                        ("complete_task", "tasks:write"), ("delete_task", "tasks:write"),
                        ("update_task", "tasks:write"), ("reopen_task", "tasks:write"),
                        ("clear_completed_tasks", "tasks:write")]:
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


def test_tools_scope_to_the_tokens_user(client, mcp_url, bearer_for, make_user, call_tool):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    token_a, token_b = bearer_for(a), bearer_for(b)
    mine = call_tool(client, mcp_url, token_a, "add_task", {"title": "mine"})["structuredContent"]
    assert mine == {"id": mine["id"], "title": "mine", "description": None, "status": "open"}
    theirs = call_tool(client, mcp_url, token_b, "add_task", {"title": "theirs"})["structuredContent"]
    for token, expected in [(token_a, mine), (token_b, theirs), (token_a, mine)]:
        listed = call_tool(client, mcp_url, token, "list_tasks", {})
        assert listed["structuredContent"]["tasks"] == [expected]


def test_a_user_cannot_complete_another_users_task(client, mcp_url, bearer_for, make_user, call_tool):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    token_a, token_b = bearer_for(a), bearer_for(b)
    made = call_tool(client, mcp_url, token_b, "add_task", {"title": "theirs"})
    other_id = made["structuredContent"]["id"]
    result = call_tool(client, mcp_url, token_a, "complete_task", {"task_id": other_id})
    assert result.get("isError") is True
    assert result["content"][0]["text"] == f"Error executing tool complete_task: Task not found: {other_id}"
    still = call_tool(client, mcp_url, token_b, "list_tasks", {"status": "open"})
    assert still["structuredContent"]["tasks"] == [made["structuredContent"]]


def test_list_tasks_uses_one_status_vocabulary(client, mcp_url, bearer_for, make_user, call_tool):
    token = bearer_for(make_user("a@example.com", "pw"))
    made = call_tool(client, mcp_url, token, "add_task", {"title": "job"})["structuredContent"]
    completed = call_tool(client, mcp_url, token, "complete_task", {"task_id": made["id"]})
    expected = {**made, "status": "completed"}
    assert completed["structuredContent"] == expected
    assert call_tool(client, mcp_url, token, "list_tasks", {"status": "completed"})["structuredContent"] == {"tasks": [expected]}
    assert call_tool(client, mcp_url, token, "list_tasks", {"status": "open"})["structuredContent"] == {"tasks": []}
    assert call_tool(client, mcp_url, token, "complete_task", {"task_id": made["id"]})["structuredContent"] == expected


@pytest.mark.parametrize("name,arguments,scope", [
    ("list_tasks", {}, "tasks:write"),
    ("add_task", {"title": "denied"}, "tasks:read"),
    ("complete_task", {}, "tasks:read"),
    ("delete_task", {}, "tasks:read"),
    ("update_task", {}, "tasks:read"),
    ("reopen_task", {}, "tasks:read"),
    ("clear_completed_tasks", {}, "tasks:read"),
    ("list_tasks", {}, ""),
    ("add_task", {"title": "denied"}, "tasks:write:extra"),
])
def test_tools_require_their_scope(client, mcp_url, bearer_for, make_user, make_task, call_tool,
                                 name, arguments, scope):
    user = make_user("a@example.com", "pw")
    task = make_task(user, "untouched", "open")
    task_id = str(task.id)
    token = bearer_for(user, scope)
    if name in ("complete_task", "delete_task", "reopen_task"):
        arguments = {"task_id": task_id}
    elif name == "update_task":
        arguments = {"task_id": task_id, "title": "denied"}
    result = call_tool(client, mcp_url, token, name, arguments)
    assert result.get("isError") is True
    required_scope = "tasks:read" if name == "list_tasks" else "tasks:write"
    assert f"Missing required scope: {required_scope}" in result["content"][0]["text"]
    full_token = bearer_for(user)
    assert call_tool(client, mcp_url, full_token, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": task_id, "title": "untouched", "description": None, "status": "open"}],
    }


def test_tools_accept_only_the_scope_they_need(client, mcp_url, bearer_for, make_user, call_tool):
    user = make_user("a@example.com", "pw")
    write = bearer_for(user, "tasks:write")
    made = call_tool(client, mcp_url, write, "add_task", {"title": "job"})["structuredContent"]
    done = call_tool(client, mcp_url, write, "complete_task", {"task_id": made["id"]})["structuredContent"]
    read = bearer_for(user, "tasks:read")
    assert call_tool(client, mcp_url, read, "list_tasks", {})["structuredContent"] == {"tasks": [done]}


def test_missing_task_returns_tool_error(client, mcp_url, bearer, call_tool):
    task_id = str(uuid4())
    result = call_tool(client, mcp_url, bearer, "complete_task", {"task_id": task_id})
    assert result.get("isError") is True
    assert result["content"][0]["text"] == f"Error executing tool complete_task: Task not found: {task_id}"


@pytest.mark.parametrize("name,arguments", [
    ("list_tasks", {"status": "complete"}),
    ("complete_task", {"task_id": "not-a-uuid"}),
    ("add_task", {"title": None}),
])
def test_tools_reject_invalid_arguments(client, mcp_url, bearer, call_tool, name, arguments):
    result = call_tool(client, mcp_url, bearer, name, arguments)
    assert result.get("isError") is True
    assert call_tool(client, mcp_url, bearer, "list_tasks", {})["structuredContent"] == {"tasks": []}


@pytest.mark.parametrize("name", ["add_task", "list_tasks", "complete_task"])
def test_task_database_failure_rolls_back_and_hides_details(
    client, mcp_url, bearer_for, make_user, make_task, call_tool, monkeypatch, name,
):
    from sqlalchemy.exc import SQLAlchemyError

    from app import tasks

    user = make_user("a@example.com", "pw")
    task = make_task(user, "untouched", "open")
    task_id = str(task.id)
    token = bearer_for(user)
    operation = getattr(tasks, name)

    def fail_after_operation(*args):
        operation(*args)
        raise SQLAlchemyError("private database details")

    arguments = {"add_task": {"title": "rolled back"}, "list_tasks": {},
                 "complete_task": {"task_id": task_id}}[name]
    with monkeypatch.context() as patch:
        patch.setattr(tasks, name, fail_after_operation)
        result = call_tool(client, mcp_url, token, name, arguments)
    assert result.get("isError") is True
    assert result["content"][0]["text"] == f"Error executing tool {name}: Task operation failed"
    assert call_tool(client, mcp_url, token, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": task_id, "title": "untouched", "description": None, "status": "open"}],
    }


def test_delete_task_removes_and_returns_the_callers_task(
    client, mcp_url, bearer_for, make_user, make_task, call_tool,
):
    user = make_user("a@example.com", "pw")
    task = make_task(user, "typo", "open")
    token = bearer_for(user)
    deleted = call_tool(client, mcp_url, token, "delete_task", {"task_id": str(task.id)})
    assert deleted["structuredContent"] == {
        "id": str(task.id), "title": "typo", "description": None, "status": "open",
    }
    assert call_tool(client, mcp_url, token, "list_tasks", {})["structuredContent"] == {"tasks": []}


@pytest.mark.parametrize("tool_name", ["delete_task", "update_task", "reopen_task"])
def test_write_tools_hide_other_users_tasks_and_missing_ids(
    client, mcp_url, bearer_for, make_user, make_task, call_tool, tool_name,
):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    task = make_task(b, "theirs", "completed")
    token_a = bearer_for(a)
    arguments = {"task_id": str(task.id)}
    if tool_name == "update_task":
        arguments["title"] = "changed"
    result = call_tool(client, mcp_url, token_a, tool_name, arguments)
    assert result.get("isError") is True
    assert result["content"][0]["text"] == (
        f"Error executing tool {tool_name}: Task not found: {task.id}"
    )
    token_b = bearer_for(b)
    assert call_tool(client, mcp_url, token_b, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": str(task.id), "title": "theirs", "description": None, "status": "completed"}],
    }


def test_update_task_changes_title_or_description(client, mcp_url, bearer_for, make_user, make_task, call_tool):
    user = make_user("a@example.com", "pw")
    task = make_task(user, "old", "open")
    token = bearer_for(user)
    updated = call_tool(client, mcp_url, token, "update_task", {
        "task_id": str(task.id), "title": "new", "description": "notes",
    })
    assert updated["structuredContent"] == {
        "id": str(task.id), "title": "new", "description": "notes", "status": "open",
    }
    cleared = call_tool(client, mcp_url, token, "update_task", {
        "task_id": str(task.id), "description": "",
    })
    assert cleared["structuredContent"] == {
        "id": str(task.id), "title": "new", "description": "", "status": "open",
    }


def test_update_task_rejects_empty_update(client, mcp_url, bearer_for, make_user, make_task, call_tool):
    user = make_user("a@example.com", "pw")
    task = make_task(user, "unchanged", "open")
    token = bearer_for(user)
    result = call_tool(client, mcp_url, token, "update_task", {"task_id": str(task.id)})
    assert result.get("isError") is True
    assert "At least one of title or description is required" in result["content"][0]["text"]
    assert call_tool(client, mcp_url, token, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": str(task.id), "title": "unchanged", "description": None, "status": "open"}],
    }


def test_reopen_task_returns_completed_task_to_open(client, mcp_url, bearer_for, make_user, make_task, call_tool):
    user = make_user("a@example.com", "pw")
    task = make_task(user, "resume", "completed")
    token = bearer_for(user)
    expected = {"id": str(task.id), "title": "resume", "description": None, "status": "open"}
    assert call_tool(client, mcp_url, token, "reopen_task", {"task_id": str(task.id)})["structuredContent"] == expected
    assert call_tool(client, mcp_url, token, "reopen_task", {"task_id": str(task.id)})["structuredContent"] == expected


def test_clear_completed_tasks_deletes_only_callers_completed_tasks(
    client, mcp_url, bearer_for, make_user, make_task, call_tool,
):
    a = make_user("a@example.com", "pw")
    b = make_user("b@example.com", "pw")
    open_task = make_task(a, "keep", "open")
    make_task(a, "done 1", "completed")
    make_task(a, "done 2", "completed")
    other = make_task(b, "theirs", "completed")
    token_a, token_b = bearer_for(a), bearer_for(b)
    assert call_tool(client, mcp_url, token_a, "clear_completed_tasks", {})["structuredContent"] == {"deleted": 2}
    assert call_tool(client, mcp_url, token_a, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": str(open_task.id), "title": "keep", "description": None, "status": "open"}],
    }
    assert call_tool(client, mcp_url, token_b, "list_tasks", {})["structuredContent"] == {
        "tasks": [{"id": str(other.id), "title": "theirs", "description": None, "status": "completed"}],
    }


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


def test_mcp_supports_the_initialize_handshake(client, mcp_url, bearer):
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
    assert r.json()["result"]["structuredContent"] == {"tasks": []}
