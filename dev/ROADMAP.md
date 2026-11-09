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

## v0.3.0 - Static files and the finish step
Exit: a site serves its assets and pages with correct caching and security headers.
- [ ] Static mounts before routing: hardened joining (no escape from the root, symlinks checked), MIME by extension, `ETag`/`Last-Modified`, conditional requests (304, 412), single ranges (206, 416), precompressed `.br`/`.gz` variants, cache headers.
- [ ] Health endpoints (liveness, readiness) before routing.
- [ ] Security headers policy with defaults (CSP, frame, referrer, permissions, HSTS on HTTPS).
- [ ] `Cx::set_cookie` through cookie-net; `Cx::not_modified(etag)` fast path.
- [ ] parse-net for `If-None-Match`, `If-Modified-Since`, `Range`.

## v0.4.0 - Actions: forms, uploads, CSRF
Exit: a login form and an avatar upload run as form-net's alpha routes describe (`form-net/tests/alpha_routes.rs`), CSRF enforced.
- [ ] form-net: `Cx::form::<T>()`, uploads, per-route limits, inspectors.
- [ ] csrf-sec: origin policy and session-bound token on unsafe methods; opt-out only with a reason; the body is unreadable before the check passes.
- [ ] Actions: 303 after an accepted form, 422 re-render with errors.
- [ ] External redirect allowlist.

## v0.5.0 - Negotiation, CORS, compression, caching, several sites
- [ ] `Accept` for error replies (HTML or JSON); `Accept-Language` locale.
- [ ] CORS per group; preflight.
- [ ] Compression through compress-lib for direct deployments.
- [ ] `CachePolicy` per route; cacheability report for a cache in front; per-variant cache seam.
- [ ] A site table choosing the app by host and base path.
- [ ] More hook points (before render, after the response through serve-net's `done`).

## v0.6.0 - Performance
- [ ] criterion benchmarks: normalization, lookup at 10,000 routes, pipeline overhead, error page; baselines recorded.
- [ ] Remove the per-request host copy; allocation-free hot path verified by a counting allocator test.
- [ ] Adopt a serve-net reply buffer API if available (PLAN O-4).

## v0.7.0 - Hardening
- [ ] Attack tests for every threat in PLAN section 13.
- [ ] Property tests: two spellings reach one route; normalization idempotent and never above the root.
- [ ] Fuzz targets: normalization, routing, query decoding, cookie reading; 24 hours each, no findings.
- [ ] `docs/SECURITY.md`.

## v0.8.0 - Alpha
- [ ] A template engine implementing `Render` in use; a gate implementation in use; form-net's alpha routes running in web-net.
- [ ] An example site with sign-in, a form, an upload, static files, and themed error pages.

## v0.9.0 - Beta
- [ ] Pre-1.0 polish pass: every accepted gap, deferred item, and missed target revisited.
- [ ] Adversarial review, findings fixed test-first.
- [ ] `dev/READINESS-1.0.md` for James.

## v1.0.0 - Stable
- [ ] James's decision, after the first site has run on it end to end.
