# ADR-001: Maintain a Flask Modular Monolith

## Status

Accepted

## Context

The application is an existing internal operational portal containing multiple tools including:

- Authentication and user administration
- CSIRT
- VirusTotal
- Cisco Umbrella
- Vault

The application currently runs as a single Flask application while separating functional domains through Flask Blueprints and subsystem-specific modules.

The current major functional boundaries are:

```text
auth
main
csirt
virustotal
umbrella
vault
```

Several subsystems intentionally share:

- authentication
- authorization
- SQLAlchemy
- audit logging
- notifications
- application configuration
- database models

There is currently no demonstrated requirement for independent service deployment, independent scaling, or network-level separation between these modules.

## Decision

Continue developing the application as a **modular Flask monolith**.

New functionality should normally be added inside an existing subsystem or as a new Flask Blueprint when it represents a genuinely new functional domain.

Do not introduce:

- microservices
- separate backend applications
- independent service databases
- network APIs between internal modules

unless a concrete operational requirement justifies the additional complexity.

## Expected Structure

Functional modules should continue following the existing pattern:

```text
app/
├── <subsystem>/
│   ├── __init__.py
│   ├── routes.py
│   ├── logic.py       # when needed
│   └── ...
```

Subsystem-specific implementation should remain local whenever reasonable.

Cross-cutting infrastructure should remain shared.

## Consequences

### Benefits

- Lower operational complexity
- Easier deployment
- Shared authentication and authorization
- Shared database transactions
- Simpler local development
- Easier cross-module workflows
- Fewer distributed-system failure modes

### Costs

- Modules remain deployed together
- Some shared-code coupling is unavoidable
- Background workloads share application infrastructure
- Scaling one module independently is difficult

These costs do not currently justify service decomposition.

## Agent Guidance

Agents must not propose or implement service decomposition merely because it appears architecturally cleaner.

A transition away from the modular monolith requires a new ADR supported by concrete requirements such as:

- independent scaling
- different availability requirements
- separate security boundaries
- separate deployment lifecycles
- material operational bottlenecks