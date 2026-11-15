# Database Design

LightBWS uses SQLite as a single-node OLTP record system through SeaORM. WAL mode permits concurrent
readers while SQLite serializes writes; foreign keys and schema-on-write constraints preserve the
authorization graph. The database is the source of truth. Web responses, SDK sync output, and remote
backup objects are derived views.

## Normalized Model

- `organizations` contains the single official SDK organization identity and the check value that binds the database to its instance organization key.
- `users`, `sessions`, `groups`, and `group_members` model human identity and group inheritance.
- `user_totp` holds at most one authenticator secret per user, encrypted with the instance master
  key, and the last accepted time step so a code cannot be replayed. `user_recovery_codes` stores
  only digests. `login_challenges` holds short-lived, digest-identified sign-in steps that are
  waiting for a second factor.
- `projects` belongs to the organization; `secrets` belongs to exactly one project. A secret does not
  duplicate `organization_id`, so project and secret organization membership cannot diverge.
- `secret_versions` keeps a bounded history of each secret's earlier key, value, and note in the
  same plaintext-or-ciphertext representation as `secrets`. It stores the project and the actor
  that replaced the version as snapshots without foreign keys, so removing a project, user, or
  machine never rewrites history.
- Project and direct-secret policies use separate normalized join tables for users, groups, and
  machines. Composite primary keys are the uniqueness constraint and support resource-first reads.
- Reverse indexes support actor-first permission evaluation without scanning every policy.
- `machine_accounts` stores only credential digests. `machine_sessions` stores only bearer-token
  digests and cascades when an account is removed.
- `sdk_sync_state` provides one atomic, monotonically increasing revision allocator.
- `audit_settings` is the singleton retention policy for audit collection. `audit_events` is
  immutable application data until a controlled cleanup transaction opens the deletion guard;
  actor identifiers deliberately remain as snapshots after an actor is removed.
- `backup_targets` owns encrypted credentials and scheduling state. `backup_jobs` is the execution
  record and enforces one running job per target.

## Referential Actions

- Removing a user or group cascades membership and grants, immediately revoking inherited access.
  Removing a user also cascades their second factor and pending sign-in challenges.
- Removing a machine cascades sessions and grants.
- Purging a project cascades its secrets; purging a secret cascades direct grants and its version
  history.
- Organization removal is restricted while projects exist.
- Backup target removal cascades its operational job history by explicit product policy.
- Audit event deletion is blocked by a database trigger unless the cleanup guard is enabled inside
  the same transaction. Closing audit logging stops new inserts but does not silently erase history.

Project lifecycle changes and SDK revision allocation commit in one transaction. Secret queries join
or authorize through the project lifecycle, so a deleted project cannot expose a child secret while
restoring the project preserves secrets that had already been individually deleted.

## Constraints

- Plaintext and SDK-ciphertext representations are mutually exclusive.
- Every secret has a project.
- Policy `write` requires `read`.
- Roles, actor kinds, audit outcomes, target kinds, trigger kinds, and job states are closed enums.
- Every Boolean column is constrained to SQLite integers `0` or `1`; persisted grant rows always
  include read access and may optionally include write access.
- Entity timestamps are monotonic, SDK revisions cannot move backward, and audit retention is
  limited to 1-3650 days.
- Scheduled targets have a bounded positive interval and no due timestamp while disabled.
- Running, successful, and failed backup jobs have state-consistent completion/error/size fields.
- Usernames, group names, machine names, and backup target names are unique case-insensitively.

## Index Rationale

- Session expiry has its own leading-column index because cleanup is global; `(actor_id, expires_at)`
  remains for revocation.
- Project and secret list indexes match equality filters followed by `updated_at DESC` ordering.
- Every grant table's primary key serves resource-first policy views; reverse indexes serve actor-first
  authorization checks.
- Partial indexes cover due backup targets and one-running-job enforcement.
- Audit indexes support newest-first global, actor, and resource timelines.
- Composite membership and grant tables use `WITHOUT ROWID`, keeping one clustered B-tree instead
  of a rowid table plus a duplicate composite-primary-key index.

## Transaction Boundaries

- Secret writes and global SDK revision allocation commit together. A write that changes the key,
  value, or note stores the replaced content as a version and prunes versions beyond the configured
  limit in the same transaction.
- Project trash/restore and child secret state/revision changes commit together.
- Group membership and policy replacement validate all references before delete-and-insert and commit
  atomically.
- Backup job completion and target schedule/status updates commit together.
- Manual and automatic audit cleanup authorize deletion, remove matching events, close the guard,
  and record the cleanup timestamp in one transaction.
- Import validates records and applies the complete data set in one transaction; any constraint or
  validation failure rolls back all changes.

## Table-by-Table Review

| Table | Record role | Enforced invariants and primary access path |
| --- | --- | --- |
| `organizations` | SDK organization identity and organization-key check | Fixed-width identifier, bounded non-empty name, bounded key check, restricted project deletion |
| `users` | Human identities | Case-insensitive username uniqueness, role/Boolean checks, monotonic account timestamps, active-admin lookup index |
| `user_totp` | Authenticator secret per user | One row per user, bounded ciphertext, confirmation not before creation, non-negative replay step, user cascade |
| `user_recovery_codes` | One-time recovery codes | Digest-only codes unique per user, use not before creation, user cascade |
| `login_challenges` | Sign-in steps awaiting a second factor | Digest-only identifiers, expiry after creation, non-negative failure count, bounded state, user cascade, global expiry index |
| `sessions` | Web bearer sessions | Digest-only identifiers, expiry after creation, user cascade, user and global expiry indexes |
| `projects` | Secret grouping and policy boundary | Exactly one plaintext/ciphertext representation, organization FK, soft-delete timeline, organization/list index |
| `secrets` | Sensitive key-value records | Exactly one project, bounded plaintext/ciphertext representation, soft-delete timeline, project/list/revision indexes |
| `secret_versions` | Earlier content of a secret | Unique `(secret_id, version)`, same representation and length checks as `secrets`, closed actor kinds, `replaced_at` not before `valid_from`, cascade on secret purge |
| `machine_accounts` | Non-human identities | Unique name/client ID, digest-only credential, creator restriction, revocation/compatibility checks |
| `machine_sessions` | SDK bearer sessions | Digest-only identifiers, expiry after creation, account cascade, account and global expiry indexes |
| `groups` | User inheritance groups | Case-insensitive name uniqueness and monotonic timestamps |
| `group_members` | Group-to-user membership | Composite uniqueness, cascaded revocation, reverse user lookup, no duplicate rowid B-tree |
| `project_*_grants` | Project policies for users/groups/machines | Composite uniqueness, read-required/write-optional checks, bidirectional indexes, cascaded revocation |
| `secret_*_grants` | Direct Secret policies for users/groups/machines | Composite uniqueness, read-required/write-optional checks, bidirectional indexes, cascaded revocation |
| `machine_*_grants` | Human visibility of machine accounts | Composite uniqueness, read-required/write-optional checks, reverse grantee indexes, cascaded revocation |
| `sdk_sync_state` | Global monotonic revision allocator | Singleton organization row, non-negative revision, trigger-enforced monotonic updates |
| `audit_settings` | Audit collection and retention policy | Singleton row, 1-3650 day retention, cleanup guard, monotonic policy/cleanup timestamps |
| `audit_events` | Security and authorization history | Immutable updates, guarded deletes, bounded actor/resource snapshots, global/actor/resource timelines |
| `backup_targets` | Encrypted remote backup configuration | Valid JSON, encrypted credentials, exact scheduler state, bounded interval and lifecycle timestamps |
| `backup_jobs` | Backup execution history | One running job per target, state-consistent result fields, target/global newest-first indexes |

`tests/database_design.rs` inventories every record table and attacks each table's constraints with
invalid direct SQL. `tests/audit_retention.rs` verifies disabled collection, guarded manual cleanup,
retention cleanup, and cleanup throttling.

SQLite `synchronous=NORMAL` with WAL is chosen for a portable self-hosted service: committed
transactions survive process crashes, while an operating-system or power failure may lose the most
recent WAL transaction. Operators requiring maximum power-loss durability can place the data
directory on durable storage and back it up remotely; LightBWS never presents SQLite as a replicated
or distributed database.
