# The taskboard hosts its own OAuth 2.1 authorization server

The same application that serves the website and the MCP endpoint also acts as the OAuth 2.1 authorization server for the ChatGPT Connection, using the existing email + password login as its identity source. This keeps one User store and one login instead of running a separate identity service.

## Considered Options

- **Managed or bundled IdP** (Auth0, Logto, Zitadel, Keycloak) — rejected for now: another stateful service to operate for three Users. Revisit if the User base grows past a small trusted group.
