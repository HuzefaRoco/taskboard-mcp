# ChatGPT connects through an OAuth 2.1 authorization server

The taskboard's MCP endpoint is treated as a production resource server. A User's ChatGPT obtains access tokens from an OAuth 2.1 authorization server that issues tokens scoped to the taskboard, instead of presenting a shared static bearer token.

## Considered Options

- **Static per-User bearer token** — simplest, and still per-User isolated, rejected: not a supported production path for the ChatGPT connector, and offers no rotation or revocation.
- **Single shared static token** — rejected: every User would read and write the same tasks.
