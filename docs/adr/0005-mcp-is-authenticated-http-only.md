# MCP is an authenticated, HTTP-only surface

The MCP endpoint is served over Streamable HTTP at `/mcp`. Every Task tool requires an OAuth 2.1 access token carrying the `tasks:read` and `tasks:write` scopes, declared per tool. ChatGPT registers its own OAuth client through Dynamic Client Registration, so no client is configured by hand.

## Consequences

- The stdio transport and the `say_hello` tool were removed: stdio only served local clients, and `say_hello` had no place in a hosted, authenticated service.
- CIMD was not implemented; Dynamic Client Registration covers ChatGPT's default path without fetching client metadata from a URL.
