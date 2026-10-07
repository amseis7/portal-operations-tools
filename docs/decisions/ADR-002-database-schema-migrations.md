# ADR-002: Database Schema Changes Must Use SQLAlchemy and Alembic Migrations

## Status

Accepted

## Context

The application uses:

```text
SQLAlchemy
Flask-Migrate
Alembic
```

Database models are part of the application source code and migration history is maintained under:

```text
migrations/
migrations/versions/
```

The application already contains production data and existing schema history.

Direct manual modification of database schemas would make application models, migration history, and deployed databases inconsistent.

## Decision

All persistent schema changes must be represented through:

1. SQLAlchemy model changes
2. A new Alembic migration

Agents and developers must not directly modify a production database schema as the primary implementation method.

Historical migrations must not normally be rewritten.

## Required Workflow

For a schema change:

```text
understand existing model
        ↓
modify SQLAlchemy model
        ↓
generate/create migration
        ↓
review upgrade()
        ↓
review downgrade()
        ↓
consider existing data
        ↓
test migration
```

## Existing Data

Migrations must assume databases can contain existing production records.

Changes involving:

- NOT NULL columns
- uniqueness
- foreign keys
- column removal
- data format changes
- encrypted data

must explicitly consider existing rows.

## Consequences

### Benefits

- Reproducible schema evolution
- Environment consistency
- Reviewable database changes
- Upgrade history
- Lower risk of application/schema divergence

### Costs

- Schema changes require migration work
- Some changes require data migration logic
- Rollback behavior must be considered

## Agent Guidance

An agent must not:

- edit SQLite/database files directly
- replace existing migrations to make a new feature easier
- assume a clean database
- delete historical migrations without explicit instruction

When models and migration history appear inconsistent, report the inconsistency before making assumptions.