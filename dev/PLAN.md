# web-net - Project Plan

> The design, strategy, and decision record for `web-net`. A living document: every design decision, idea, or open question about web-net is written here or in [`ROADMAP.md`](./ROADMAP.md) before it is acted on.
>
> **Read order:** [`../REPS.md`](../REPS.md) &rarr; [`DIRECTIVES.md`](./DIRECTIVES.md) &rarr; **this file** &rarr; [`ROADMAP.md`](./ROADMAP.md).
>
> **Status:** `0.3.0`, static files and the finish step. Core and design lock at `0.2.0`. The plan below was revised at 0.2.0 (D-005 to D-020): hooks replace middleware, a gate trait replaces per-crate adapters, and rendering reads typed views.

---

## Contents

1. [Purpose](#1-purpose)
2. [web-net and serve-net](#2-web-net-and-serve-net)
3. [The request path](#3-the-request-path)
4. [URL handling](#4-url-handling)
5. [The router](#5-the-router)
6. [Gates: authentication and authorization](#6-gates-authentication-and-authorization)
7. [Handlers and the context](#7-handlers-and-the-context)
8. [Hooks instead of middleware](#8-hooks-instead-of-middleware)
9. [Rendering](#9-rendering)
10. [Errors](#10-errors)
11. [Events and checkpoints](#11-events-and-checkpoints)
12. [Built-in pieces still to come](#12-built-in-pieces-still-to-come)
13. [Threats](#13-threats)
14. [Architecture](#14-architecture)
15. [Ecosystem and dependencies](#15-ecosystem-and-dependencies)
16. [Costs](#16-costs)
17. [Testing](#17-testing)
18. [Open decisions](#18-open-decisions)
19. [Decision log](#19-decision-log)

---

## 1. Purpose

web-net is what a site is written in. It takes a request from serve-net, decides which site and which route it is for, checks who is asking and whether they may, runs the route's handler, renders the page, and answers every refusal and error the same way. It makes the secure way the easy way: a route cannot exist without declared access, a handler only ever sees a request that passed its gate, and two spellings of a path cannot reach different routes.

web-net is generic. Any application with its own authentication, template engine, or detection layer plugs them in through traits; web-net names none of them.

---

## 2. web-net and serve-net

| | serve-net | web-net |
|---|---|---|
| knows | sockets, listeners, connections, ingress modes, the HTTP engine, admission, revocation before dispatch and before the reply | sites, canonical paths, routes, gates, handlers, pages |
| owns | the connection, framing (`content-length`, `connection`), keep-alive, the trusted client address and scheme | everything between "request complete" and "reply ready" |
| never sees | which route matched | a socket, a listener, or which front end the request came through |

An `App` is a `serve_net::HttpService`, so it runs on serve-net as it is. A wrapper with its own service (one that authenticates before the web layer, for example) calls `App::respond` or `App::respond_identified` from its `call`, and `App::classify` from its `head` for dispatch decisions before admission. In tests the whole pipeline runs in memory through `serve_net::testing`, no sockets.

---

## 3. The request path

One fixed path. Each step answers or hands on; nothing runs that the request does not need.

| # | Step | Fails with | Notes |
|---|---|---|---|
| 1 | site | 421 unknown host; 301/308 to the canonical host or to HTTPS | host table from the builder; the base path is removed here |
| 2 | url | 400 malformed; 301/308 to the canonical spelling | section 4 |
| 2a | early | 404 for a missing file; 405 for a method other than `GET`/`HEAD` | health paths and static files, before the gate (section 12) |
| 3 | authenticate | the gate's denial (403 for a ban) | skipped by `respond_identified` |
| 4 | route | 404 | section 5 |
| 5 | method | 405 + `Allow`; 501 for an unknown method | `HEAD` follows `GET`; `OPTIONS` answered automatically |
| 6 | authorize | 303 to sign-in, 401 + challenge, 403, 404 (hidden), other 4xx | not called for public routes |
| 7 | checkpoint | the checkpoint's status | `Stage::Authorized` |
| 8 | hooks `Routed` | the hook's error | only hooks registered for this route |
| 9 | handler | the handler's error; 500 on panic | writes into a reply web-net holds |
| 10 | render | 500 | `Stage::BeforeRender` checkpoint first |
| 11 | hooks `Finish` | the hook's error | add headers |
| 12 | finish | 500 for an invalid field | the reply is copied to serve-net; `x-content-type-options: nosniff` and the security headers, except fields the handler set |

Still to come on this path (roadmap): CSRF after authorize (0.4), the cache fast path after authorize (0.5). The handler's own conditional fast path is `Cx::not_modified` (0.3).

Why authentication runs before routing: a ban, an expired session, or a forged token is caught before any route code or route lookup, and the router never needs to know about credentials. The cost is one gate call for requests that end in 404; a gate keeps that cheap (an in-memory session lookup).

---

## 4. URL handling

| Job | Rule | Why |
|---|---|---|
| host | the authority (absolute-form target or `Host`) is matched against the declared hosts, case-insensitively, a trailing dot ignored, any port unless the declared host names one | one site per address set |
| aliases | an alias is redirected to the first declared host (301, 308 for unsafe methods) | one address per page |
| unknown host | 421 when hosts are declared; with none declared the site answers any host | a site never serves a host it does not own |
| development | `localhost`, `127.0.0.1`, `[::1]`, `*.localhost` are the site only on a builder marked `development()`; HTTPS is not required for them | production never trusts "localhost" in a `Host` field |
| HTTPS | `https_only()` redirects plain HTTP to `https://` on the canonical host; it needs a declared host, so a redirect is never built from the request's `Host` | no host-header poisoning through redirects |
| base path | `/blog`: removed before routing, added back by `Cx::url` and every redirect; `/blog` itself is redirected to `/blog/`; paths outside get 404 | the site works installed in a folder and moves without editing routes |
| decoding | percent-escapes decoded once; the decoded bytes must be UTF-8; `%2F` (encoded slash), `%5C` and a raw `\`, and any control character are refused with 400 | double decoding and encoded separators are classic routing and traversal bypasses |
| canonical form | each decoded segment re-encoded one way: RFC 3986 `pchar` bytes (unreserved, sub-delims, `:`, `@`) written as they are, every other byte as upper-case `%XX` | each path has exactly one spelling, so route literals compare byte for byte |
| dot segments | `.` and `..` removed after decoding (`%2e%2e` is `..`), never above the root | `..` can never escape a folder |
| empty segments | `//` collapses | one URL per page |
| trailing slash | one policy per site: `Strip` (default), `Add` (not for a last segment with a dot), `Ignore` | one URL per page, unless the site says otherwise |
| case | `lowercase_paths()` redirects paths with upper-case letters | for sites that promise lower-case URLs |
| redirect | any path not in canonical form is redirected to it, query kept: 301 for `GET` and `HEAD`, 308 otherwise | users and search engines see one address; a POST keeps its method and body |
| query | read on demand by `Cx::query`: `+` is a space, escapes decoded; a name that appears twice is a 400 | most pages never read the query; parameter pollution is refused, never resolved |

The fast path: a path with no `%`, no empty segment, no dot segment (and no upper case when the site is lower case) is canonical as it is, and is routed without allocating.

---

## 5. The router

- Patterns: literal segments, parameters `:name` (one segment), a wildcard `*name` at the end (the rest of the path, zero or more segments). At most 8 parameters per pattern. Literals are written decoded and stored canonical.
- Compiled at build time into a segment trie. Precedence: literal, then parameter, then wildcard; when a branch fails further down, the next kind is tried. Each trie node is visited at most once per lookup, so the work is bounded by the path length and the table size, and a lookup allocates nothing (parameters are byte ranges into the path).
- Methods: a table per path, indexed by method. `HEAD` uses the `GET` handler unless the route has its own (serve-net sends the headers and the length without the body). `OPTIONS` is answered with 204 and `Allow` unless the route has its own; `OPTIONS *` with the union of all routes. `CONNECT` and `TRACE` cannot be routed.
- Build-time checks, all reported at once: a malformed pattern, a route with no handler, a route with no declared access, two handlers for one method of one path, an unknown template.
- Two patterns that differ only in parameter names share a trie node; each method keeps its own names.

---

## 6. Gates: authentication and authorization

```rust
pub trait Identity: Send + Sync + 'static {
    fn is_guest(&self) -> bool;
    fn csrf_binding(&self) -> Option<&[u8]> { None }
}

pub trait Gate: Send + Sync + 'static {
    type Identity: Identity;
    type Rule: Send + Sync + 'static;
    fn authenticate(&self, req: &Request<'_>) -> Result<Self::Identity, Denial>;
    fn authorize(&self, who: &Self::Identity, rule: &Self::Rule, req: &Request<'_>) -> Result<(), Denial>;
}
```

- One trait with two checkpoints, so an application has one type parameter (`App<G>`). An implementation joins its authentication and authorization crates; web-net names neither.
- `Open` is the default gate: every visitor is a `Guest`, and its rule type (`NoRule`) has no values, so only public routes can be declared.
- Every route declares `.public()` or `.allow(rule)`; groups give a default. A route with neither stops the build (D-002 kept).
- A handler receives a `Cx`, which only web-net can make, and only after the access check passed. Skipping the gate does not compile.
- `Denial::{sign_in, forbidden, hidden, status}(code)`. `sign_in` on a `GET` or `HEAD` with a sign-in page configured is a 303 to it with `next` (the site-relative path and query, percent-encoded); otherwise 401 with the configured `WWW-Authenticate` challenge (default `Session`). `status` accepts 4xx only; anything else becomes 403, so a gate cannot turn a denial into a success.
- `Request::cookie(name)` reads through cookie-net and refuses ambiguity: a name twice, or two `Cookie` fields, is `Err(Ambiguous)`, never a pick.
- `respond_identified` is for a caller that authenticated already; web-net trusts the identity it is given and still authorizes every route that is not public.
- Fail closed: a gate backed by remote state denies when it cannot decide.

---

## 7. Handlers and the context

- A handler is `Fn(&mut Cx<'_, I>) -> web_net::Result` (or any `Handler<I>`). Synchronous: serve-net's workers run it; a route declares `.work(WorkClass::Io | Cpu)` so a dispatcher in front can move slow work off the connection's worker (`App::classify`).
- `Cx` reads: method, canonical path, fields, identity, reference, parameters (`param`, `param_as` with 404 on a value that does not parse), query, body.
- `Cx` writes into a reply web-net holds (status, fields, body), copied to serve-net only when the handler and its hooks succeed. An error or a panic discards it whole: a cookie or header set before the failure never leaves.
- Fields are checked as they are set: a name that is not a token, a value with a control character, or a framing field (`content-length`, `transfer-encoding`, `connection`, `keep-alive`, `upgrade`) turns the reply into a 500.
- Redirects from handlers (`see_other`, `redirect`) take site-relative paths only: one leading `/`, never `//` or `/\`, visible ASCII. The base path is added. Redirects to other hosts come later, through an allowlist (0.4).
- The reply buffers are reused per thread between requests (taken for one request and put back, so nothing about a request stays there). `wipe_buffers()` zeroes them after every request.

---

## 8. Hooks instead of middleware

Middleware is a chain every request walks, whether or not a link has anything to do with it. A hook is a named point in the fixed path where registered code runs only for the routes it registered for (D-006, superseding the middleware sections of the 0.1 plan).

| Hook | Runs | Typical use |
|---|---|---|
| `Routed` | after the access check and checkpoint, before the handler | locale, an A/B variant, feature flags |
| `Finish` | after the handler succeeded | add headers |

Selection: `Routes::all()`, `Routes::prefix("/blog")` (segment-aware: `/blog` and `/blog/...`, never `/blogger`), `Routes::named(&[...])`. The builder compiles them into each route's lists; a route with no hooks pays nothing, a hook for ten routes costs nothing on the others. More points (before render, after the response) arrive with the steps they belong to.

Request id, access log, timing, CORS, security headers, CSRF, and compression, which were middleware in the 0.1 plan, become fixed steps (security headers, CSRF, compression), serve-net's job (request id, timing via its observer), or events (access log).

---

## 9. Rendering

```rust
pub trait Render: Send + Sync + 'static {
    fn template(&self, name: &str) -> Option<TemplateId>;
    fn render(&self, template: TemplateId, view: &dyn View, out: &mut Output<'_>) -> Result<(), RenderError>;
}

pub trait View {
    fn shape(&self) -> &dyn Shape;
    fn get(&self, key: Key) -> Value<'_>;
    fn call(&self, key: Key, args: &[Value<'_>], with: &mut dyn FnMut(Value<'_>)) { /* Absent */ }
}
```

- No JSON between data and engine (D-007). Building a text document from typed data and parsing it back costs tens of microseconds per page [est.] and loses every type. An engine resolves the names a template uses to `Key`s once (through the view's `Shape`, cached per `ShapeId`) and reads values by key while rendering.
- `Value`: absent, bool, int, float, text, trusted HTML (`SafeHtml::trusted`, greppable), a computed `Display`, a nested view, a list. `call` passes its result to a closure, so a method can return a value computed for the call.
- Templates a route names (`.template("post")`) are resolved at build; an unknown one stops the build. `Cx::render(&view)` renders the route's template; `render_named` resolves per call.
- `Output` writes into the reply body with a page budget (default 8 MiB, `page_limit`).
- Escaping for each output context is the engine's job, with raw output behind an explicit marker. This is where cross-site scripting is prevented.
- web-net has no engine and no template dependency. An engine implements `Render` in its own crate; third-party engines plug in through adapter crates that walk a `View` into their value type (D-004 revised).

---

## 10. Errors

- Handlers return `web_net::Error`: a status (400 to 599; anything else is 500), a stable code, an optional source. `From<Denial>` and `From<RenderError>` exist.
- One function answers every refusal and error: the status, the engine's `error/<status>` template if it has one (view fields `status`, `title`, `message`, `reference`), otherwise a built-in page that cannot fail. The visitor sees the generic title and message and the reference; never the code or the source. Error replies carry `cache-control: no-store`.
- The reference is the connection id (hex) and the request number: `1a2b-3`.
- A panic in a hook or handler is caught; the request gets a 500, the reply it had started is discarded, and a `Panicked` event is reported.
- `BuildError` lists every problem in the declaration, each with its subject (`GET /admin`, `host`) and what to do.

---

## 11. Events and checkpoints

- `Events::event(&Event)`: kind (`Refused`, `Denied`, `Failed`, `Panicked`, `Revoked`), reference, route pattern, status, code, and the source error for logs. No request bytes. Security components must hear what web-net turns away, so every refusal is reported, not only failures (D-012).
- `Checkpoint::check(&Envelope, Stage) -> serve_net::Verdict` at `Stage::Authorized` and `Stage::BeforeRender`, for revocation that arrives while a request is in flight (a ban, a revoked session, a lockdown). serve-net's own checkpoint covers admission and the moment before the reply leaves. A checkpoint backed by remote state denies when the remote cannot be reached.

---

## 12. Built-in pieces

| Piece | Version | Detail |
|---|---|---|
| static files | 0.3 (done) | section 12.1 |
| health | 0.3 (done) | `health(path)`: `200 ok`; `ready(path, check)`: `200 ready` or `503 not ready`; `GET`/`HEAD` only, `no-store`, before the gate |
| security headers | 0.3 (done) | section 12.2 |
| cookies out | 0.3 (done) | `Cx::set_cookie(&SetCookie)`; cookie-net is re-exported as `web_net::cookie_net` so the versions match |
| conditional fast path | 0.3 (done) | `Cx::not_modified(tag)` sets `ETag` and answers 304 when `If-None-Match` matches (weak comparison, `GET`/`HEAD`) |
| forms and uploads | 0.4 | form-net: `Cx::form::<T>()`, multipart uploads, per-route limits, inspectors |
| CSRF | 0.4 | csrf-sec: origin policy plus a session-bound token on every unsafe method unless the route opts out with a reason; the body cannot be read before the check |
| actions | 0.4 | the accepted form answers 303, the refused one re-renders with 422 |
| external redirects | 0.4 | an allowlist of hosts |
| negotiation | 0.5 | `Accept` (HTML or JSON error replies), `Accept-Language` locale |
| CORS | 0.5 | per group; preflight answered |
| compression | 0.5 | compress-lib, for direct deployments (a proxy in front usually compresses) |
| caching | 0.5 | `CachePolicy` per route; a cacheability report from `respond_identified` so a cache in front can store guest pages; a per-variant cache seam |
| several sites | 0.5 | a site table choosing the app by host and base path |

### 12.1 Static files

- `Assets::new(mount, dir)`, added with `Builder::assets`. Served in the early step, before the gate and the router: files are public. A route under a mount stops the build (it could never run).
- The path is canonical already (section 4). Each decoded segment is checked again for what file systems read specially, on every platform so a site behaves the same everywhere: a leading dot (`.env`, `.git`; `hidden_files(true)` allows them), `:` (Windows alternate data streams and drive letters), a trailing dot or space (Windows drops them, so `secret.txt.` would open `secret.txt`), `\`, NUL, and the Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`, with any extension). Any of them is a 404.
- The joined path is resolved (`canonicalize`) and must still be under the resolved root, so a symbolic link cannot lead out of the folder. Links that stay inside work. The window between the check and the open is only reachable by someone who can write into the folder.
- A folder is a 404 unless the mount has an `index` file. There are never listings.
- Validators: a strong `ETag` from the length, the modification time (nanoseconds), and the coding; `Last-Modified`. `If-None-Match` (weak comparison) answers 304; without it, `If-Modified-Since` does. Malformed conditions are ignored, as RFC 9110 says.
- Ranges (`GET` only): one range is a 206 with `Content-Range`; an unsatisfiable one a 416 with `bytes */length`; several ranges, or an `If-Range` that does not match, get the whole file (RFC 9110 lets a server ignore `Range`). `Accept-Ranges: bytes`.
- Precompressed variants (default on): with `Accept-Encoding`, `file.br` or `file.gz` next to the file is served with `Content-Encoding`, its own `ETag`, and `Vary: accept-encoding`. Without the field, the plain file.
- `Cache-Control` per mount (default `no-cache`: kept and revalidated).
- Files up to `INLINE_LIMIT` (1 MiB) are read whole; larger ones go out in 64 KiB parts through serve-net's streamed reply. Each part is read at the offset serve-net reports as sent, so nothing is held between parts; a file that shrinks under the reply closes the connection.
- MIME by extension (`mime_for`), with `charset=utf-8` for text types; anything unknown is `application/octet-stream`, and `nosniff` stops the browser guessing.

### 12.2 Security headers

`SecurityHeaders` (builder `security_headers`) applies to every reply web-net sends: pages, error pages, files, redirects, `OPTIONS`. A field the handler set itself wins. Defaults:

| Field | Default |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=(), payment=()` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Strict-Transport-Security` | `max-age=31536000`, on HTTPS replies only and never for a development host |
| `X-Content-Type-Options` | `nosniff`, always (also with `SecurityHeaders::none()`) |

Cost: about 400 bytes per reply and one comparison per field against the handler's fields.

---

## 13. Threats

| Threat | Defence | Status |
|---|---|---|
| path tricks bypassing route rules | one normalization before routing; canonical redirect; encoded slash, backslash, controls refused | 0.2 |
| `..` escaping a folder | dot segments removed after decoding, never above the root | 0.2 |
| forgotten authorization | access declared on every route or the build fails; `Cx` only after the gate | 0.2 |
| host-header poisoning | unknown hosts 421; redirects use declared hosts only | 0.2 |
| open redirects | handler redirects site-relative only (`//` and `/\` refused) | 0.2; allowlist 0.4 |
| information leaks in errors | generic pages and a reference; codes and sources only to events | 0.2 |
| half-written replies after a failure | the reply is held and discarded on error or panic | 0.2 |
| header injection | reply fields checked as they are set; framing fields refused | 0.2 |
| parameter pollution | a repeated query name is a 400 | 0.2 |
| cookie tossing | a cookie name twice, or two `Cookie` fields, is ambiguous and never picked | 0.2 |
| CSRF | session-bound token and origin policy on unsafe methods | 0.4 |
| XSS | contextual escaping in the engine; a strict CSP by default | engine; 0.3 (done) |
| clickjacking | frame headers by default | 0.3 (done) |
| directory traversal in static files | canonical path, segment rules, resolved path checked against the root | 0.3 (done) |
| hidden and special files | dot files, alternate data streams, trailing dots and spaces, device names refused | 0.3 (done) |
| protocol downgrade | HSTS on HTTPS replies | 0.3 (done) |
| resource exhaustion | serve-net's limits; web-net's page budget, segment limit (256), parameter limit (8), field limit (64) | 0.2 |

Every row has an attack test by 0.7.

---

## 14. Architecture

```
src/
  lib.rs       crate docs, re-exports
  app.rs       App, Builder, the pipeline, hooks, classify, health, the error function
  assets.rs    static files: resolution, validators, ranges, variants, parts, MIME
  headers.rs   SecurityHeaders
  url.rs       normalization, canonical encoding, TrailingSlash
  router.rs    pattern parsing, the segment trie, captures
  gate.rs      Identity, Gate, Denial, Open, Guest
  request.rs   Request (what gates and handlers read), RequestId, cookie reading
  cx.rs        Cx (the handler context), the held reply, query decoding
  route.rs     Route, Group, Handler, get/post/put/patch/delete
  render.rs    Render, View, Shape, Value, List, SafeHtml, Fields, Output, RenderError
  events.rs    Events, Event, Checkpoint, Stage
  error.rs     Error, BuildError, the built-in error page
```

---

## 15. Ecosystem and dependencies

| Crate | Since | Why |
|---|---|---|
| serve-net 0.7 (`http1`) | 0.2 | the server; `HttpService`, requests, replies, the testing helpers; http-net through its re-export |
| cookie-net 0.7 | 0.2 | reading the `Cookie` field; `SetCookie` (re-exported) from 0.3 |
| parse-net 0.9.2 | 0.3 | entity tags, HTTP dates, `Range` and `If-Range`, `Accept-Encoding`; later `Accept` and media types |
| form-net 0.9 | 0.4 | forms and uploads |
| csrf-sec 0.9 | 0.4 | CSRF tokens and origin policy |
| compress-lib 0.9 | 0.5 | response compression |

No third-party runtime dependency. First-party crates at published versions only. No template engine: engines depend on web-net, not the other way round.

---

## 16. Costs

Every number is an estimate until the 0.6 benchmarks.

| Step | Cost [est.] | Allocation |
|---|---|---|
| host match | 20-50 ns | one small lower-case copy of the authority (to be removed in 0.6) |
| canonical path check (fast path) | 10-50 ns | none |
| non-canonical path (redirect) | 0.3-1 µs | the canonical string; the request ends with the redirect |
| route lookup | 20-100 ns | none |
| method and access dispatch | a few ns, plus the gate's own time | none |
| hooks | zero for a route with none | none |
| held reply copy to serve-net | ~1 ns per byte (one memcpy) | none after warm-up (buffers reused per thread) |
| `wipe_buffers` | one pass over the bytes written | none |
| error page | ~1 µs | the page body |

The held reply costs one copy of the body. It buys the guarantee that a failed handler leaves nothing behind. If serve-net grows a way to clear a reply's fields (or hands out its body buffer), the copy can go; requested from serve-net (O-4).

---

## 17. Testing

- In-process pipeline tests through `serve_net::testing` (`tests/pipeline.rs`): routing, params, methods, HEAD, OPTIONS, redirects, refusals, sites, gates, sign-in, `respond_identified`, build errors, error replies, panics, hooks, render, checkpoints, classify.
- Unit tests per module: normalization (every rule, idempotence), patterns, trie precedence and backtracking.
- From 0.7: property tests (two spellings reach one route; normalization is idempotent and never rises above the root), fuzz targets for normalization, routing, and query decoding, and an attack test for every threat.
- From 0.6: criterion benchmarks for normalization, lookup at 10,000 routes, and the pipeline overhead per request.

---

## 18. Open decisions

| Id | Question | Recommendation |
|---|---|---|
| O-2 | Handlers synchronous? | yes; slow work is declared with `.work()` and moved by a dispatcher in front (answered at 0.2) |
| O-4 | Ask serve-net for a reply body buffer handed out (or a reply reset) so the held reply's copy can go | yes, for serve-net 0.8 or 0.9 |
| O-5 | Redirect status for a non-canonical `GET`: 301 or 308 | 301 (universally cached and understood); 308 for unsafe methods |
| O-6 | Should 405 and automatic `OPTIONS` answer before authorization (revealing a route's methods to anyone)? | yes, as now: CORS preflights carry no credentials, and the methods of a route are not a secret; a route that must stay hidden uses `Denial::hidden` and its own `OPTIONS` |

---

## 19. Decision log

| Id | Date | Decision | Reason |
|---|---|---|---|
| D-001 | 2026-10-13 | web-net is the web layer; serve-net is the server | sockets and deployment never leak into application code |
| D-002 | 2026-10-13 | Every route declares its access; the build fails otherwise | nothing becomes reachable by omission |
| D-003 | 2026-10-13 | Loading a record and checking access is one call | object-level checks must be the easy path (planned with the gate implementations, not in 0.2) |
| D-004 | 2026-10-13, revised 2026-11-08 | Rendering behind a trait; web-net ships no engine and depends on none; engines (first or third party) implement `Render` in their own crates | the engine is replaceable and web-net stays at zero third-party dependencies |
| D-005 | 2026-11-08 | The request path is fixed (section 3) and every step is a function call | predictable cost per request; nothing runs that the request does not need |
| D-006 | 2026-11-08 | Hooks per route replace middleware | a route with no hooks pays nothing; no chain every request walks |
| D-007 | 2026-11-08 | Rendering reads typed views by key; no JSON | no serialize-and-parse per page, no lost types |
| D-008 | 2026-11-08 | One `Gate` trait with `authenticate` and `authorize`; `App<G>` has one type parameter; `Open` is the default | the simplest generic shape; an implementation can join two crates behind it |
| D-009 | 2026-11-08 | `Cx` is the proof of a cleared request: only web-net constructs it, after the access check | skipping the gate does not compile |
| D-010 | 2026-11-08 | `respond_identified` for callers that authenticate before the web layer | a front layer authenticates once for every service; web-net still authorizes per route |
| D-011 | 2026-11-08 | Non-canonical paths are redirected, not routed; routing only ever sees canonical paths | two spellings cannot reach different routes, and literals compare byte for byte |
| D-012 | 2026-11-08 | Every refusal, denial, failure, and panic is an event | detection must see probes, not only failures |
| D-013 | 2026-11-08 | Dot segments are removed (the newer design), not refused (the 0.1 plan) | RFC 3986 behaviour; the redirect makes the canonical path visible, and `..` never rises above the root |
| D-014 | 2026-11-08 | `%2F`, `%5C` and raw `\`, and every control character are refused, not decoded | encoded separators and controls are bypasses, never legitimate in a page path |
| D-015 | 2026-11-08 | The handler's reply is held by web-net and discarded on error or panic | a failure never sends half a reply (a cookie set before the error) |
| D-016 | 2026-11-08 | Handler redirects are site-relative only | open redirects are impossible from a string passed along |
| D-017 | 2026-11-08 | A repeated query name is a 400; an ambiguous cookie is an error | ambiguity is refused, never resolved by picking |
| D-018 | 2026-11-08 | Development hosts are trusted only on a builder marked `development()` | production never trusts "localhost" |
| D-019 | 2026-11-08 | `https_only` needs a declared host | a redirect is never built from the request's `Host` |
| D-020 | 2026-11-08 | Authentication runs before routing | bans and forged credentials are caught before any route code; the router knows nothing about credentials |
| D-021 | 2026-11-08 | Health paths and static files are answered before the gate and the router | they are public and must stay cheap under load; a route under a mount is a build error |
| D-022 | 2026-11-08 | Asset segments that file systems read specially are refused on every platform, and the resolved path must stay under the resolved root | one behaviour everywhere; no symbolic-link or Windows-name escape |
| D-023 | 2026-11-08 | No directory listings; an index file only when the mount names one | listings leak what a folder holds |
| D-024 | 2026-11-08 | Strict security headers by default; HSTS only on HTTPS and never for development hosts; a handler's own field wins | secure by default without pinning `localhost` to HTTPS in a browser |
| D-025 | 2026-11-08 | Precompressed variants only when the client sent `Accept-Encoding`; each variant has its own `ETag`; `Vary` always on such mounts | caches never mix codings; clients that send no field get the plain file |
| D-026 | 2026-11-08 | Files over 1 MiB go out in 64 KiB parts, each read at serve-net's sent offset | no per-reply state and bounded memory per connection |
| D-027 | 2026-11-08 | One range per request; several ranges get the whole file | multipart byte ranges are rare and a known amplification vector; RFC 9110 allows ignoring `Range` |
| D-028 | 2026-11-08 | cookie-net is re-exported for `Cx::set_cookie` | the caller's `SetCookie` is always the version web-net encodes |
