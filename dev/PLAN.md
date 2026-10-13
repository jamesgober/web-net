# web-net - Project Plan

> The design, strategy, and decision record for `web-net`. A living document: every design decision, idea, or open question about web-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** scaffold, `0.1.0`. Design lock is `0.2.0`.

---

## Contents

1. [Purpose](#1-purpose)
2. [web-net and serve-net](#2-web-net-and-serve-net)
3. [Routing](#3-routing)
4. [Handlers and extractors](#4-handlers-and-extractors)
5. [Middleware](#5-middleware)
6. [Security built into the API](#6-security-built-into-the-api)
7. [Built-in pieces](#7-built-in-pieces)
8. [Rendering](#8-rendering)
9. [Errors](#9-errors)
10. [Threats](#10-threats)
11. [Architecture](#11-architecture)
12. [Ecosystem and dependencies](#12-ecosystem-and-dependencies)
13. [First run: the thin slice](#13-first-run-the-thin-slice)
14. [Testing](#14-testing)
15. [Open decisions](#15-open-decisions)
16. [Decision log](#16-decision-log)

---

## 1. Purpose

web-net is what a site is written in. It gives application code routes, handlers, middleware, and the small pieces every site needs, and it makes the secure way the easy way: a route cannot exist without a declared contract and permission, and loading a record comes with its access check.

---

## 2. web-net and serve-net

| | serve-net | web-net |
|---|---|---|
| knows | sockets, listeners, connections, ingress modes, protocol engines | routes, handlers, the request a route receives |
| owns | the per-connection engine, the fixed pipeline slots, lifecycle | slot 6 (the application) and the HTTP adapters for the security slots |
| never sees | which route matched | a socket, a listener, or which front end the request came through |

web-net runs inside serve-net. It can also be driven in tests with no server at all.

---

## 3. Routing

- Routes are declared up front and compiled at startup into a segment tree: static segments first, then parameters (`/users/:id`), then wildcards (`/static/*path`).
- Matching is linear in the number of path segments and allocation-free.
- Method dispatch per route; a path that matches with the wrong method returns 405 with an `Allow` header; no match returns 404.
- Path normalization happens once, before matching (percent-decoding rules, dot segments refused, duplicate slashes per policy), so two spellings of a path cannot reach different routes or bypass a rule.
- Conflicting routes are a startup error, not a runtime surprise.
- Route groups share a prefix, middleware, and default declarations.

---

## 4. Handlers and extractors

- A handler is a function from a context to a response or an error. Handlers are synchronous to start (the blocking driver); an async form arrives with the reactor if measurements justify it.
- **Extractors** turn parts of a request into typed values, and fail with a clean 400 when they cannot:

| Extractor | Source |
|---|---|
| path parameters | the router, parsed into declared types |
| query | the URL crate (planned), typed |
| headers | http-net views |
| cookies | cookie-net |
| form fields and uploads | form-net, inspected by customs-sec |
| JSON body | jsonx-lib, inspected by customs-sec |
| session and subject | gate-net and gate-sec, from the pipeline |
| request id, client address | serve-net |

---

## 5. Middleware

- Ordered layers around handlers: global, per group, per route.
- Every layer boundary is a bouncer-io checkpoint, so a request revoked mid-flight is stopped at the next layer, as the connection gate's design requires.
- Built-in layers: request id, access log, timing, CORS, security headers, CSRF, compression (later; Apache compresses in front for the first run).

---

## 6. Security built into the API

| Rule | How web-net enforces it |
|---|---|
| every route has a contract | a route declaration includes its customs-sec contract; the app refuses to start without one |
| every route has a permission | a route declaration includes its gate-sec action; the app refuses to start without one (public routes declare `public` explicitly) |
| object checks are not forgotten | `ctx.load_checked(&repo, id, Action::READ)` loads a record and checks access in one call; the plain load is not the easy path |
| CSRF | state-changing methods require the session-bound token from gate-net unless the route opts out with a reason |
| security headers | applied by default from shield-sec's policy |
| errors leak nothing | section 9 |

The HTTP adapters for serve-net's security slots live here: where the session cookie is read, how a customs refusal becomes a 422 page, how gate-sec's denial becomes a 403.

---

## 7. Built-in pieces

| Piece | Detail |
|---|---|
| static files | hardened path joining (path-lib), `ETag` and `Last-Modified`, conditional requests, ranges, precompressed variants, cache headers, MIME by extension |
| MIME and negotiation | extension table, `Accept` handling |
| CORS | declared per route group; preflight handled |
| health endpoints | liveness and readiness from serve-net's core |
| redirects, trailing slash policy | declared, never implicit |

---

## 8. Rendering

- A `Render` trait: template name and data in, bytes out.
- First run: a third-party template engine behind the trait, loosely coupled, in its own module and feature.
- Later: James's own render library implements the same trait; nothing else changes.
- Rendering uses context-aware escaping; this is where XSS is prevented (customs-sec does not rewrite markup).

---

## 9. Errors

- Handlers return typed errors; each maps to a status and a generic page.
- Every error response carries a correlation id; details go only to logs and the error core.
- Panics in handlers are caught at the slot boundary and become a 500 for that request only.

---

## 10. Threats

| Threat | Defence |
|---|---|
| path tricks bypassing route rules | one normalization before matching; dot segments refused |
| forgotten authorization | declarations required at startup; `load_checked` |
| CSRF | session-bound token required on state-changing methods |
| XSS | context-aware escaping in rendering; security headers (content security policy) |
| clickjacking | frame headers by default |
| open redirects | redirect targets must be relative or on an allowlist |
| information leaks in errors | generic pages, correlation ids |
| directory traversal in static files | path-lib hardened joining |

---

## 11. Architecture

```
src/
  lib.rs        crate docs, Tier-1 entry points (App)
  app.rs        App builder, route declarations, startup checks
  router.rs     segment tree, matching, normalization
  handler.rs    Handler trait, Context
  extract/      path, query, header, cookie, form, json, session
  middleware/   layers: request id, log, timing, cors, headers, csrf
  adapters/     HTTP adapters for serve-net's pipeline slots
  statics.rs    static files
  mime.rs       MIME table and negotiation
  render.rs     Render trait
  error.rs      WebError (#[non_exhaustive]), error pages
  test.rs       in-process request builder for tests
```

---

## 12. Ecosystem and dependencies

serve-net, http-net, cookie-net, form-net, jsonx-lib, path-lib, gate-net, gate-sec, customs-sec, bouncer-io, a URL crate and an encodings crate (both planned), and the render engine behind a feature.

---

## 13. First run: the thin slice

Router, handlers, path and query and form and JSON extractors, cookies and sessions, the security adapters for every slot, `load_checked`, static files, security headers, CSRF, error pages, health endpoints, and the render trait with one engine behind it.

---

## 14. Testing

- Router: precedence, conflicts, normalization, 404 and 405, at 10,000 routes.
- A startup check fails for any route missing a contract or permission.
- Middleware: a revocation between any two layers stops the request.
- Every threat in section 10 has a test that must fail to exploit.
- In-process tests drive the whole app without sockets.

---

## 15. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-1 | Which third-party template engine for the first run? | the smallest well-maintained engine with auto-escaping; chosen at design lock |
| O-2 | Handlers sync only until the reactor exists? | yes |
| O-3 | Publish `0.1.0` to crates.io to claim the name? | yes |

---

## 16. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | web-net is the framework; serve-net is the engine | sockets and deployment never leak into application code |
| D-002 | 2026-10-13 | Routes must declare a contract and a permission; startup fails otherwise | nothing becomes reachable by omission |
| D-003 | 2026-10-13 | Loading a record and checking access is one call | object-level checks must be the easy path |
| D-004 | 2026-10-13 | Rendering behind a trait | the first-run engine can be replaced by James's own without touching the rest |
