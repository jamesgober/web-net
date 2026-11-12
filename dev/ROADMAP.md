# web-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.
>
> Revised at 0.2.0 to the newer design (PLAN D-005 to D-020): hooks instead of middleware, one gate trait, typed views for rendering. The 0.1 roadmap's "0.3 thin slice" is split across 0.2 to 0.5.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Core and design lock (DONE, 2026-11-08)
Exit: a site answers real requests on serve-net with canonical URLs, a router, 404/405, gates, hooks, render through a trait, and one error path; the public API in `docs/API.md`.
- [x] Site: hosts, aliases, 421, development hosts, HTTPS redirect, base path.
- [x] URL normalization: decode once, refusals, dot segments, empty segments, trailing-slash policy, lower case, canonical redirects (301/308).
- [x] Router: compiled trie, literal/param/wildcard precedence with backtracking, 404, 405 + `Allow`, automatic `HEAD` and `OPTIONS`, 501.
- [x] Gates: `Identity`, `Gate`, `Denial`, `Open`; access declared on every route; `Cx` only after the gate; sign-in redirect and 401 challenge; `respond_identified`; `classify`.
- [x] Handlers and `Cx`: params, query, body, held reply, field checks, local redirects, `url`.
- [x] Hooks `Routed` and `Finish` with route selectors.
- [x] Render: `Render`, `View`, `Shape`, `Value`, `List`, `SafeHtml`, `Fields`, `Output` with a budget; route templates resolved at build; error templates.
- [x] Errors and events: one error function, built-in page, reference, `Events`, `Checkpoint`.
- [x] Example on a real socket; pipeline tests in memory.

## v0.3.0 - Static files and the finish step (DONE, 2026-11-08)
Exit: a site serves its assets and pages with correct caching and security headers.
- [x] Static mounts before routing: segment rules, resolved path inside the root, MIME by extension, `ETag`/`Last-Modified`, conditional requests (304), single ranges (206, 416), precompressed `.br`/`.gz` variants, cache headers, large files in parts.
- [x] Health endpoints (liveness, readiness) before routing.
- [x] Security headers policy with defaults (CSP, frame, referrer, permissions, opener, HSTS on HTTPS).
- [x] `Cx::set_cookie` through cookie-net; `Cx::not_modified(tag)` fast path.
- [x] parse-net for `If-None-Match`, `If-Modified-Since`, `Range`, `If-Range`, `Accept-Encoding`.
- Moved to 0.4: `412 Precondition Failed` for `If-Match` and `If-Unmodified-Since` on unsafe methods. Reason: they protect state-changing requests, which arrive with the 0.4 actions; static files take `GET` and `HEAD` only.

## v0.4.0 - Actions: forms, uploads, CSRF (DONE, 2026-11-08)
Exit: a login form and an avatar upload run as form-net's alpha routes describe (`form-net/tests/alpha_routes.rs`), CSRF enforced.
- [x] form-net: `Cx::form::<T>()`, `form_inspected`, `Cx::upload` (feature `uploads`), per-route limits, inspectors.
- [x] csrf-sec: origin policy and session-bound token on unsafe methods; opt-out only with a reason; the body is unreadable before the check passes.
- [x] Actions: 303 after an accepted form, 422 re-render with errors.
- [x] External redirect allowlist.
- [x] `If-Match` / `If-Unmodified-Since` on unsafe methods (412), moved from 0.3.
- The alpha routes' customs inspector is a test double here (`tests/actions.rs`), as in form-net: the real content inspector plugs into `form_inspected` when it exists. Running both routes for two weeks on a real site is form-net's and web-net's 0.8 alpha exit.

## v0.5.0 - Negotiation, CORS, compression, caching, several sites (DONE, 2026-11-08)
- [x] `Accept` for error replies (HTML or JSON); `Cx::language`, `Cx::media`.
- [x] CORS per route and group; preflight.
- [x] Compression through compress-lib for direct deployments (gzip).
- [x] `CachePolicy` per route and group; `App::serve` and `Served` with the cacheability report for a cache in front.
- [x] `Sites`: applications chosen by host and base path.
- [x] `Hook::BeforeRender`.
- Not done, with reasons (PLAN D-038, D-041): Brotli for dynamic replies (no encoder in compress-lib; revisit if one is added); an after-response hook (serve-net's observer and web-net's events cover it). A per-variant cache inside web-net is not planned: the report lets a cache in front do it, and keeping one in web-net would duplicate it.

## v0.6.0 - Performance (DONE, 2026-11-08)
- [x] criterion benchmarks (`benches/web.rs`): pipeline overhead against bare serve-net, 10,000 routes, a deep route, a redirect, a 404, with and without security headers; numbers in `docs/PERFORMANCE.md`.
- [x] Per-request host copies removed; precomputed `Cache-Control` values; `Accept` parsed only when it names JSON.
- [x] Allocation-free warm path verified by a counting-allocator test (`tests/alloc.rs`): 0.00 allocations per request.
- [x] The router at 10,000 routes (`tests/scale.rs`).
- Moved to 0.9 (polish pass): the quiet-machine rerun with the per-step split, because the machine stayed loaded by other jobs through this release; numbers taken under load are kept only as relative. Moved to when serve-net offers it: the reply buffer API (PLAN O-4).

## v0.7.0 - Hardening (DONE, 2026-11-09)
- [x] Attack tests for every threat in PLAN section 13 (`tests/attacks.rs`, T-1 to T-15).
- [x] Property tests: every spelling reaches one path; normalization idempotent and clean; decoding inverts encoding; lookup sound and complete.
- [x] Fuzz targets `request` (normalization, routing, gates, cookies, query, CSRF, forms through whole requests) and `path` (no redirect loops, no gate bypass). See the release notes for the hours run.
- [x] `docs/SECURITY.md`.
- [x] An independent adversarial review of `src/`, findings fixed test-first.
- [x] `Identity::set_cookie`, `Denial::with_cookie` (asked for by a gate implementation).
- Moved to 0.9 (polish pass): fuzzing to 24 hours per target. Reason: the machine is shared and loaded; 0.7 ships after a shorter clean run, and the 0.9 polish pass runs both targets the full 24 hours on the final code.

## v0.8.0 - Alpha (DONE, 2026-11-09)
- [x] A template engine in use: Luminess renders the example site's pages straight into the reply (`Cx::body_mut`). `Render` gained a generic associated view type so Luminess can implement it directly, typed (D-058); its glue lands behind a feature in Luminess against web-net 0.8.
- [x] A gate implementation: gatekeeper-io's `impl web_net::Gate` (its feature `web-net`) compiles and builds an `App` against 0.8 with only its version pin moved (checked locally; gatekeeper-io is not on crates.io yet, so nothing in this repository depends on it).
- [x] form-net's alpha routes (login urlencoded with its token; avatar multipart with the token before the file) run in web-net (`tests/actions.rs`, `examples/site.rs`).
- [x] Freeze review of the public API: `#[non_exhaustive]` on the structs web-net makes (`Event`, `Served`, `Classified`, `Problem`); `Cx::next_path` for sign-in pages.
- Not met, with reasons: a site running on web-net in production (needs the platform it serves to be deployed: James), and gatekeeper-io from crates.io (its repositories are James's to create).
- [x] An example site with sign-in, a form, an upload, and static files (`examples/site.rs`, shipped in 0.7), rendered by Luminess through `Cx::body_mut`. Themed error pages wait for an engine that implements `Render`.

## v0.9.0 - Beta (DONE, 2026-11-10)
- [x] Pre-1.0 polish pass, every accepted gap and deferred item revisited:
  - fixed: `Sites` and lower-case sites (D-059); a missing asset no longer answers chunked (the in-flight table replaced the `stream()` probe);
  - documented: CSRF always strict (D-060), buffered request bodies only (O-8), `CachePolicy::Public` is public for signed-in visitors too;
  - kept, with reasons in the plan: no after-response hook (D-041), no per-variant cache in web-net (the cacheability report), gzip only (D-038);
  - waiting on other crates, asked for: serve-net's reply buffer (O-4) and explicit abort (O-7), a Brotli encoder in compress-lib.
- [x] Both fuzz targets 24 hours on the final code (moved from 0.7).
- [x] Adversarial review, findings fixed test-first (two independent reviews in 0.7, eleven defects fixed; a form-net cross-review in 0.7).
- [x] `dev/READINESS-1.0.md` for James.
- Moved to 0.9.x, with the reason: benchmarks on a quiet machine with the per-step split. The shared machine has not been quiet through any release; the numbers in `docs/PERFORMANCE.md` stay relative until it is.

## v0.10.0 - Simplified (DONE, 2026-11-11)
- [x] Simplicity audit of every public item (`dev/SIMPLICITY-0.10.md`): S-1 to S-14 fixed.
- [x] `App::listen`, writers that return `Result`, `.public()` only where a gate has rules, one way per job, plain names.
- [x] `docs/API.md` rewritten as a compiled reference; the README compiles too.
- [x] Migration note (`CHANGELOG.md`, `docs/release/v0.10.0.md`); the dependents told.

## v0.10.x - Until 1.0
- [ ] A site in production on web-net for two weeks (James).
- [ ] The gate crates on crates.io, and a test against them here (James: repositories).
- [ ] Quiet-machine benchmarks.
- [ ] `examples/site.rs` renders through Luminess's `Render` implementation (`luminess::web::Theme`, themed error pages) once Luminess accepts web-net 0.9 (asked: `>=0.8, <0.10`).

## v1.0.0 - Stable
- [ ] James's decision, after the first site has run on it end to end.
