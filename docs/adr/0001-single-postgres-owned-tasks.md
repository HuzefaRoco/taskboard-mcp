# Tasks live in one Postgres database, owned per User

All Users share a single Postgres database. Each Task row records the User who owns it, and every read and write is scoped to the authenticated User.

## Considered Options

- **Schema per User** and **database per User** — stronger isolation, rejected: migrations, connection routing, and backups multiply, which is hard to justify for a small trusted user base. Either can be added later if the trust model changes.
