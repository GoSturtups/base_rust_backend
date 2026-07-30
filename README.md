# base_rust_backend

A reusable **GraphQL backend boilerplate** in Rust, designed to be dropped into
other projects. It provides users/auth, a queued SMTP mailer, push
notifications, and lightweight internationalization on top of
**Axum + [async-graphql](https://async-graphql.github.io/) + PostgreSQL**.

async-graphql was chosen because it is the mature Rust GraphQL library that
supports **queries, mutations _and_ subscriptions** (a hard requirement here).

## Why PostgreSQL

The task allowed pushing back on the DB choice. **Postgres is the right default**
for this workload: the modules need relational integrity (users ↔ devices ↔
queued notifications), transactional queue claiming (`FOR UPDATE SKIP LOCKED`,
used by both workers), array columns (`permissions TEXT[]`), and easy horizontal
read scaling — all first-class in Postgres and used throughout. No feature here
would benefit from a document or KV store, so a second database would only add
operational cost.

## Architecture

Everything is a **feature module** under `src/`, mirroring the "HugePlugin"
pattern of the reference Kotlin backend but in idiomatic Rust:

| Module | Responsibility |
|--------|----------------|
| `core` | Config-driven DB pool + migrations, JWT, permissions, GraphQL **guards** (operation & field level), request context, error codes, the `Module` trait |
| `users` | Register/confirm/login/refresh, password reset, **Firebase** auth, permissions, paginated user list |
| `email` | Queued SMTP mailer (`lettre`) with a retrying background worker |
| `notifications` | Device registry, per-device push toggle, FCM token lifecycle, queued delivery worker with invalid-token cleanup, realtime subscription |
| `i18n` | Language resolution from the request + localized email templates |

The crate is **both a library and a binary**: import `base_backend` to embed the
server (`base_backend::build_schema`, `base_backend::http::router`) or run it
directly with the `server` binary.

Each module contributes its own GraphQL `Query`/`Mutation`/`Subscription` root;
they are merged in `src/schema.rs` (`MergedObject`). Background modules implement
`core::Module` and are started in `src/lib.rs`.

### Access control

Three levels, exactly as required:

* **public** — no guard (e.g. `register`, `login`);
* **authenticated** — `#[graphql(guard = "RequireAuth")]` (e.g. `setEmailNotifications`);
* **permission gated** — `#[graphql(guard = "RequirePermission::new(Permission::ReadUsers)")]` (e.g. the `users` list).

Individual **fields** are also gated (see `users::model::User` — `email`/`blocked`
are only visible to the user themselves or a moderator).

Error responses follow the GraphQL standard: a human-readable English message
plus a stable machine code in `extensions.code` (e.g. `wrong_credentials`,
`access_denied`) — see `core::error::codes`.

### Token verification

Access tokens are JWTs carrying `{ user id, email, permissions }`. On every
request the auth layer not only validates the JWT but also **loads the user from
the database and re-checks the email**, and rejects blocked users
(`AuthService::authenticate`).

## Running

Requirements: Rust 1.80+, PostgreSQL 13+, an SMTP relay (e.g.
[Mailpit](https://github.com/axllent/mailpit) on `localhost:1025` for dev).

```bash
createdb base_backend
cargo run --bin server          # migrations run on startup
# open http://localhost:8080/graphql for the GraphiQL playground
```

Configuration lives in `env.yaml`; any value can be overridden with an env var
(`DATABASE__URL`, `JWT__SECRET`, `EMAIL__SMTP_PASSWORD`, …).

## Request headers

The client sends, on every request:

* `Authorization: Bearer <access token>` — authentication;
* `X-Device-Id: <platform>:<id>` — the device identity for notifications
  (platform prefix + the OS device id, or a generated UUID when unavailable);
* `Accept-Language: <lang>` — user language (updated server-side per request).

For websocket subscriptions these are passed in the `connection_init` payload
(`Authorization`, `deviceId`, `language`).

## Example flow

```graphql
mutation { register(email: "a@b.com", password: "password1") { authenticated } }
# code is emailed (and logged at debug level in dev)
mutation { confirmEmail(email: "a@b.com", code: "123456") { accessToken refreshToken } }
query    { me { id email permissions } }
query    { users(limit: 20, offset: 0) { totalCount nodes { id } } }  # needs READ_USERS
subscription { notifications { title body link } }
```

## Implementation status

Fully implemented and compiling: config, DB + migrations, JWT + permissions +
guards (operation & field level), the complete users flow (register/confirm/
login/refresh/password-reset/list), email queue + SMTP worker, notifications
(devices, toggles, token lifecycle, queue + worker, subscription), i18n.

Deliberately left as clearly-marked integration points (need external
credentials/services, not core logic):

* **Firebase ID-token verification** uses the Identity Toolkit REST endpoint and
  needs a Web API key; a `DisabledFirebaseVerifier` is used until configured.
* **FCM sending** is behind the `FcmSender` trait with a `LoggingFcmSender`
  default; the HTTP v1 sender needs a service-account OAuth exchange. The queue,
  retries and invalid-token cleanup around it are complete.

## Tests

```bash
# Unit tests (JWT, permissions, i18n) — no DB required.
cargo test --test unit

# End-to-end API & security tests — boot the real GraphQL server over HTTP and
# drive it like a client. Needs a reachable Postgres (migrations run on boot;
# no SMTP/FCM needed — workers are not started and one-time codes are read from
# the DB). Point TEST_DATABASE_URL at a throwaway database:
createdb base_backend_test
TEST_DATABASE_URL=postgres://localhost:5432/base_backend_test \
  cargo test --test api

# Everything at once (integration tests still need TEST_DATABASE_URL / a DB):
TEST_DATABASE_URL=postgres://localhost:5432/base_backend_test cargo test
```

The `api` suite (`tests/api.rs`, harness in `tests/common/`) covers the security
surface end to end: registration / email-confirmation / login and input
validation; refresh-token rotation and misuse; rejection of invalid, tampered,
expired, wrong-type and email-mismatched tokens; foreign-secret forgeries; the
auth guards (unauthenticated access, permission-gated queries, field-level ACL);
the server trusting the **database over JWT claims** (revoked permissions,
blocked users, forged `Moderation`); anti-enumeration on login and password
reset; and confirmation-code brute-force throttling.
