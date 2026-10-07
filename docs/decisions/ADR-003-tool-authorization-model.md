# ADR-003: Operational Tool Access Uses UserTool and has_tool()

## Status

Accepted

## Context

Operational tools are registered centrally and access is currently modeled using:

```text
User
UserTool
User.has_tool()
```

Normal users receive explicit tool assignments.

Administrators have global tool access through:

```python
User.has_tool()
```

which returns access automatically when:

```text
user.is_admin == True
```

Most operational Blueprints are protected using:

```python
proteger_blueprint(bp, "<tool_name>")
```

Tool identifiers are also used in:

```text
app/tools_config.py
```

and user-administration workflows.

## Decision

The canonical application-level authorization mechanism for operational tools is:

```text
UserTool
+
User.has_tool()
+
proteger_blueprint()
```

New operational tools should integrate with this model rather than creating independent authorization systems.

Administrative actions should additionally use the existing administrator authorization mechanism.

## Tool Identifiers

Identifiers such as:

```text
csirt
virustotal
umbrella
vault
```

are persistent authorization identifiers.

They must not be renamed as if they were presentation-only labels.

Changing an identifier may require migration of existing `UserTool` records.

## Administrator Behavior

Administrators retain global tool access regardless of explicit `UserTool` rows.

This is deliberate current authorization behavior.

## Consequences

### Benefits

- Centralized authorization model
- Consistent administration
- Simple integration for new tools
- Avoids duplicated permission systems

### Costs

- Permission model is currently coarse-grained
- Tool-level permission does not represent fine-grained actions
- Some subsystems may additionally require ownership checks

## Ownership Is Separate

Tool permission does **not** imply unrestricted access to every object inside a tool.

Subsystems may also require:

```text
ownership
shared-resource permissions
administrator-only operations
```

For example, access to Vault entries or Umbrella job results may require additional checks.

## Known Exception

Vault currently does not consistently apply the standard Blueprint-level tool guard.

This is documented as technical debt and must not be interpreted as a new authorization model.

## Agent Guidance

Agents must not create:

- role systems
- ACL frameworks
- subsystem-specific permission tables
- duplicate authorization decorators

without a requirement that cannot reasonably be represented by the existing model.

If finer-grained authorization is required, design it explicitly rather than bypassing the current mechanism.