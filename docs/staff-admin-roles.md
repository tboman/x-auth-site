# Staff Admin Roles Specification

## Purpose

Add role-based access control to the staff side of the X-Auth admin landing page so internal users see and can use only the staff tools appropriate to their responsibilities.

The current staff admin experience should evolve from a single flat console into role-aware workspaces. A staff user may have one or more roles, and those roles determine which admin domains appear on the landing page and which staff API operations are authorized server-side.

Initial roles:

- `administrator`
- `architect`
- `executive`

Initial functionality domains:

- `tenants`
- `documents`
- `marketing`

## Goals

- Restrict staff admin functionality by role.
- Keep the staff landing page focused on the user's responsibilities.
- Support staff users with multiple roles.
- Preserve the existing staff email allowlist as an outer access gate while adding role-level authorization inside it.
- Make role assignments explicit, auditable, and durable.
- Allow future SSO group mapping without redesigning the authorization model.

## Non-Goals

- This does not replace tenant-owner access for customer workspaces.
- This does not grant customer tenant owners access to staff tools.
- This does not define complete document management, CRM, or sales pipeline implementations.
- This does not require SSO group synchronization in the first implementation phase.

## Roles

### Administrator

Administrators operate the live identity platform.

Primary domain: `tenants`

Administrators can:

- View all tenants.
- View tenant identity summaries.
- View tenant users.
- View tenant sessions.
- Inspect recent authentication activity.
- Revoke or invalidate sessions.
- Manage tenant-level operational settings where available.
- Access operational health indicators for identity services.

Default landing modules:

- Tenants
- Users
- Sessions
- Authentication activity
- Operational alerts

### Architect

Architects manage technical design, deployment planning, and platform documentation.

Primary domain: `documents`

Architects can:

- View architecture documents.
- View design documents.
- View deployment plans.
- View environment topology documentation.
- Track implementation readiness by service or platform area.
- Access diagrams and technical specifications.
- Create or update architecture and deployment notes when editing is enabled.

Default landing modules:

- Architecture
- Service topology
- Deployment plans
- Design decisions
- Compliance mappings
- Diagrams

### Executive

Executives need commercial, go-to-market, and high-level operational visibility.

Primary domain: `marketing`

Executives can:

- View pitch decks and sales collateral.
- View marketing copy and positioning assets.
- View sales pipeline summaries.
- View customer and account summaries.
- View high-level tenant growth, usage, and business metrics.
- Access read-only product and market-facing materials.

Default landing modules:

- Slides
- Sales pipeline
- Customer overview
- Product positioning
- Growth metrics

## Role-To-Domain Access

Phase 1 should keep domain access simple and role-based:

| Role | Default Domains |
|---|---|
| `administrator` | `tenants` |
| `architect` | `documents` |
| `executive` | `marketing` |

Optional cross-domain visibility may be added later through explicit permissions. The recommended future defaults are:

| Role | Tenants | Documents | Marketing |
|---|---|---|---|
| `administrator` | Full access | Optional read-only | No access |
| `architect` | Optional read-only summaries | Full access | No access |
| `executive` | Optional summary-only | Optional read-only | Full access |

Executives should remain read-only outside marketing-specific workflow actions. Architects may see technical tenant topology or usage summaries, but they must not receive user/session PII by default. Administrators may receive optional read-only document access later, but phase 1 should keep their access narrow unless there is an immediate operational need.

## Permission Model

Roles are coarse-grained bundles of permissions. Permission names should use:

```text
domain:action
```

Initial permissions:

```text
tenants:read
tenants:manage_sessions
tenants:manage_settings

documents:read
documents:write

marketing:read
marketing:view_pipeline
```

Initial role mapping:

```text
administrator:
  tenants:read
  tenants:manage_sessions
  tenants:manage_settings

architect:
  documents:read
  documents:write

executive:
  marketing:read
  marketing:view_pipeline
```

The UI should be generated from permissions, not from hardcoded email checks.

## Staff Identity And Role Assignment

The existing staff email allowlist remains the outer gate:

1. The user signs in with Google.
2. The authenticated email must be recognized as staff.
3. The system resolves the staff user's active role assignments.
4. The staff landing page renders only domains allowed by those roles.
5. Every staff API endpoint enforces the same permissions server-side.

Role assignments should be database-backed in phase 1. Environment-variable role mappings are acceptable only as a temporary bootstrap mechanism.

Recommended data model:

```sql
CREATE TABLE staff_users (
    id           UUID PRIMARY KEY,
    email        TEXT NOT NULL UNIQUE,
    display_name TEXT,
    active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE staff_user_roles (
    staff_user_id UUID NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (staff_user_id, role),
    CHECK (role IN ('administrator', 'architect', 'executive'))
);
```

A staff user may hold multiple roles.

## Admin Landing Page Behavior

After staff login:

- If the user has one role, show a focused landing page for that role's default domain.
- If the user has multiple roles, show a domain switcher containing each authorized domain.
- If the user has no active roles, show an access denied page.
- If the user is not staff, preserve the existing tenant-owner admin behavior.

Navigation should include only authorized domains:

```text
Admin
- Tenants
- Documents
- Marketing
```

The absence of a navigation item is not an authorization control. All protected staff routes and APIs must check permissions server-side.

## Domain Requirements

### Tenants Domain

Audience: `administrator`

Initial views:

- Tenant list
- Tenant detail
- Users summary
- Sessions summary
- Recent authentication activity
- Session revoke or invalidate action

Required permissions:

- `tenants:read`
- `tenants:manage_sessions` for session revocation or invalidation
- `tenants:manage_settings` for tenant operational settings

### Documents Domain

Audience: `architect`

Initial views:

- Architecture documents
- Deployment documents
- Design documents
- Diagrams
- Compliance mapping references
- Implementation readiness notes

Required permissions:

- `documents:read`
- `documents:write` for editing, publishing, or replacing documents

### Marketing Domain

Audience: `executive`

Initial views:

- Slide decks
- Sales pipeline
- Sales collateral
- Customer or account summaries
- Business metrics
- Product positioning material

Required permissions:

- `marketing:read`
- `marketing:view_pipeline`

## Authorization Requirements

- Staff roles must be enforced server-side.
- A staff user with no active role must not access any staff domain.
- Role changes should take effect on the next request or next session refresh.
- Staff sessions may include role claims only if the claims can be refreshed or invalidated safely.
- Sensitive tenant operations require `administrator`; staff allowlist membership alone is insufficient.
- Architects must not receive tenant user/session PII unless granted a future explicit permission.
- Executives must be read-only by default.
- The model must allow future mapping from external SSO groups to local roles.

## Audit Requirements

Audit staff actions that change state, along with important authorization events.

Minimum audit events:

- Staff login
- Staff access denied
- Staff role assignment changed
- Session revoked
- Session invalidated
- Tenant setting changed
- Document changed
- Marketing asset changed

Audit record fields:

```text
id
actor_email
actor_roles
action
domain
resource_type
resource_id
tenant_id
metadata
created_at
```

`tenant_id` is optional and should be set when the action is tenant-scoped.

## Staff Access Management

Phase 1 should support role assignment through seed data or a narrow staff-only access management path.

Recommended implementation order:

1. Add the database model for staff users and staff roles.
2. Seed at least one initial `administrator`.
3. Resolve roles during staff login.
4. Render the staff landing page from permissions.
5. Enforce permissions on staff APIs.
6. Add a dedicated Staff Access page for administrators.

The Staff Access page should require `administrator` and should audit all role changes.

## Acceptance Criteria

- Staff users can be assigned `administrator`, `architect`, and/or `executive`.
- A staff user may have multiple roles.
- The staff admin landing page shows only authorized domains.
- Tenant identity and session tools require `administrator`.
- Design and deployment document tools require `architect`.
- Slides and sales pipeline tools require `executive`.
- Executives are read-only by default.
- Architects do not see user/session PII by default.
- Staff users with no roles receive a clear access denied response.
- Protected staff APIs enforce permissions server-side.
- Role changes take effect on the next request or session refresh.
- Role checks are covered by tests.
- Staff role assignments and privileged actions are auditable.
