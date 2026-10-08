import json
import inspect
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import server
from mcp.server.mcpserver.exceptions import ToolError


class TaskTests(unittest.TestCase):
    def setUp(self):
        temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(temporary_directory.cleanup)
        self.db_path = Path(temporary_directory.name) / "tasks.db"
        db_path_patch = patch.object(server, "DB_PATH", self.db_path)
        db_path_patch.start()
        self.addCleanup(db_path_patch.stop)

    def test_add_task_returns_distinct_open_tasks(self):
        first = server.add_task("Write outline")
        second = server.add_task("Review outline")

        self.assertEqual(first["title"], "Write outline")
        self.assertEqual(second["title"], "Review outline")
        self.assertEqual(first["status"], "open")
        self.assertEqual(second["status"], "open")
        self.assertNotEqual(first["id"], second["id"])
        self.assertTrue(self.db_path.exists())

    def test_list_tasks_returns_two_added_tasks(self):
        first = server.add_task("Write outline")
        second = server.add_task("Review outline")

        self.assertCountEqual(
            server.list_tasks(),
            [
                {"id": first["id"], "title": "Write outline", "status": "open"},
                {"id": second["id"], "title": "Review outline", "status": "open"},
            ],
        )

    def test_list_tasks_filters_open(self):
        open_task = server.add_task("Still open")
        to_complete = server.add_task("Already done")
        server.complete_task(to_complete["id"])

        self.assertIn("status", inspect.signature(server.list_tasks).parameters)
        self.assertEqual(server.list_tasks(status="open"), [open_task])

    def test_list_tasks_filters_completed(self):
        server.add_task("Still open")
        to_complete = server.add_task("Already done")
        completed_task = server.complete_task(to_complete["id"])

        self.assertEqual(server.list_tasks(status="completed"), [completed_task])

    def test_complete_task_updates_and_returns_the_saved_task(self):
        created = server.add_task("Write outline")

        self.assertTrue(callable(getattr(server, "complete_task", None)))
        completed = server.complete_task(created["id"])

        self.assertEqual(
            completed,
            {"id": created["id"], "title": "Write outline", "status": "complete"},
        )
        self.assertEqual(server.list_tasks(), [completed])

    def test_complete_task_reports_unknown_id(self):
        self.assertTrue(callable(getattr(server, "complete_task", None)))

        with self.assertRaises(Exception) as caught:
            server.complete_task("missing-id")
        self.assertIsInstance(caught.exception, ToolError)
        self.assertEqual(str(caught.exception), "Task not found: missing-id")
        self.assertEqual(server.list_tasks(), [])

    def test_tasks_survive_a_new_server_process(self):
        create = (
            "import json, server, sys; from pathlib import Path; "
            "server.DB_PATH = Path(sys.argv[1]); "
            "print(json.dumps(server.add_task('Persist me')))"
        )
        read = (
            "import json, server, sys; from pathlib import Path; "
            "server.DB_PATH = Path(sys.argv[1]); "
            "print(json.dumps(server.list_tasks()))"
        )
        created = subprocess.run(
            [sys.executable, "-c", create, str(self.db_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        result = subprocess.run(
            [sys.executable, "-c", read, str(self.db_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        tasks = json.loads(result.stdout)
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["title"], "Persist me")
        self.assertEqual(tasks[0]["status"], "open")
        self.assertEqual(tasks[0]["id"], json.loads(created.stdout)["id"])


class ServerStartupTests(unittest.TestCase):
    def test_database_path_is_absolute_and_next_to_server(self):
        relative_launch = runpy.run_path("server.py", run_name="taskboard_test")
        self.assertEqual(
            relative_launch["DB_PATH"],
            Path(server.__file__).resolve().with_name("tasks.db"),
        )
        self.assertTrue(relative_launch["DB_PATH"].is_absolute())

    def test_default_launch_uses_stdio(self):
        self.assertTrue(callable(getattr(server, "main", None)))
        with patch.object(server.mcp, "run") as run:
            server.main([])
        run.assert_called_once_with()

    def test_http_launch_uses_loopback_and_mcp_path(self):
        self.assertTrue(callable(getattr(server, "main", None)))
        with patch.object(server.mcp, "run") as run:
            server.main(["--http"])
        run.assert_called_once_with(
            transport="streamable-http",
            host="127.0.0.1",
            port=8000,
            streamable_http_path="/mcp",
        )


if __name__ == "__main__":
    unittest.main()
