import argparse
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator, Literal
from uuid import uuid4

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError


mcp = MCPServer("taskboard-mcp")
DB_PATH = Path(__file__).resolve().with_name("tasks.db")


@contextmanager
def _database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DB_PATH)
    try:
        with connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS tasks "
                "(id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL)"
            )
            yield connection
    finally:
        connection.close()


@mcp.tool()
def say_hello(name: str) -> str:
    """Greet someone by name."""
    return f"Hello, {name}!"


@mcp.tool()
def add_task(title: str) -> dict[str, str]:
    """Create an open task and return it."""
    task_id = str(uuid4())
    task = {"id": task_id, "title": title, "status": "open"}
    with _database() as connection:
        connection.execute(
            "INSERT INTO tasks (id, title, status) VALUES (?, ?, ?)",
            (task_id, title, "open"),
        )
    return task


@mcp.tool()
def list_tasks(status: Literal["open", "completed"] | None = None) -> list[dict[str, str]]:
    """Return all tasks, or filter by open or completed status."""
    with _database() as connection:
        query = "SELECT id, title, status FROM tasks"
        parameters: tuple[str, ...] = ()
        if status is not None:
            query += " WHERE status = ?"
            parameters = ("complete" if status == "completed" else status,)
        rows = connection.execute(query + " ORDER BY rowid", parameters).fetchall()
    return [
        {"id": task_id, "title": title, "status": status}
        for task_id, title, status in rows
    ]


@mcp.tool()
def complete_task(task_id: str) -> dict[str, str]:
    """Mark a task complete and return the updated task."""
    with _database() as connection:
        row = connection.execute(
            "SELECT title FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if row is None:
            raise ToolError(f"Task not found: {task_id}")
        connection.execute(
            "UPDATE tasks SET status = ? WHERE id = ?", ("complete", task_id)
        )
    return {"id": task_id, "title": row[0], "status": "complete"}


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the taskboard MCP server")
    parser.add_argument(
        "--http",
        action="store_true",
        help="Serve Streamable HTTP at http://127.0.0.1:8000/mcp",
    )
    args = parser.parse_args(argv)

    if args.http:
        mcp.run(
            transport="streamable-http",
            host="127.0.0.1",
            port=8000,
            streamable_http_path="/mcp",
        )
    else:
        mcp.run()


if __name__ == "__main__":
    main()
