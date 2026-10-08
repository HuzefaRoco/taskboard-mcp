# Taskboard MCP

A small [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for managing tasks. Tasks are stored in a SQLite database named `tasks.db` beside `server.py`. The database and `tasks` table are created when a task tool first needs them.

## Requirements

- Python 3.11 or newer
- Node.js and `npx` if you want to use MCP Inspector
- An HTTPS tunnel or a deployed HTTPS endpoint if you want to connect from ChatGPT

## Set up

From this repository's directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows, activate the environment with `.venv\Scripts\activate` instead.

## Run the server

For an MCP client that launches local processes, use the default stdio transport:

```bash
python server.py
```

The process waits for MCP messages on standard input; it does not display a taskboard page. Configure your client to launch the absolute path to `.venv/bin/python` with the absolute path to `server.py` as its argument. Avoid a temporary virtual environment path: if it is deleted, the client will fail with `spawn ... ENOENT`.

For Streamable HTTP, run:

```bash
python server.py --http
```

The MCP endpoint is `http://127.0.0.1:8000/mcp`. Keep this terminal running while a client uses the server. Opening `/mcp` directly in a browser is not a taskboard UI and may show a protocol error.

## Available tools

| Tool | Purpose |
| --- | --- |
| `say_hello(name)` | Return a greeting. |
| `add_task(title)` | Create an open task. |
| `list_tasks(status)` | List all tasks, or filter with `open` or `completed`. |
| `complete_task(task_id)` | Mark a task complete using its ID. |

Tasks returned by `list_tasks` use the status value `complete` for completed tasks. The filter argument is `completed`.

## Test locally with MCP Inspector

Run this from the repository directory after installing the Python dependencies:

```bash
npx @modelcontextprotocol/inspector@latest .venv/bin/python server.py
```

Inspector starts the server over stdio and opens its browser interface. Select **Tools** to call `list_tasks` or the other tools. You do not need to start `python server.py` separately for this method.

Alternatively, start the HTTP server with `python server.py --http`, launch Inspector with `npx @modelcontextprotocol/inspector@latest`, then connect to `http://127.0.0.1:8000/mcp` using **Streamable HTTP**.

## Connect to ChatGPT

ChatGPT needs an endpoint it can reach; `127.0.0.1` on your computer is not reachable from ChatGPT. For local development, you can use an HTTPS tunnel:

1. Start the HTTP server: `python server.py --http`.
2. In another terminal, run `ngrok http 8000` (after [installing and configuring ngrok](https://ngrok.com/docs/getting-started/)).
3. Copy the tunnel's HTTPS address and append `/mcp`, for example `https://example.ngrok.app/mcp`.
4. On ChatGPT web, open [Plugins](https://chatgpt.com/plugins), select **+ → Add custom MCP server**, and enter a name such as `taskboard-mcp` and the HTTPS `/mcp` URL. Choose **No authentication** for this server, review the warning, and select **Create as a plugin**.
5. Install the new plugin. Start a new Work chat, type `@`, select the plugin, and try “Use taskboard-mcp to list my tasks.”

This example server does not authenticate requests. A public tunnel exposes its task tools and data to anyone who has the tunnel URL. Use it only for development, keep the URL private, and stop the tunnel when finished. For a private connection, consider [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) instead of a public URL. Account and workspace policies may affect whether custom MCP servers are available.

If you change tool names or descriptions, restart the server and refresh the plugin's tools in ChatGPT.

These ChatGPT steps follow the [OpenAI guide to adding a custom MCP server](https://developers.openai.com/api/docs/guides/custom-mcp-server) and the [MCP server quickstart](https://developers.openai.com/plugins/build/app-quickstart).
