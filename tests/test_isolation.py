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
