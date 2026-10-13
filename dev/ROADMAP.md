# web-net - Roadmap

> Path from scaffold to a stable 1.0. Hard parts are front-loaded; each phase has hard exit criteria.
> Design and decisions: [`PLAN.md`](./PLAN.md).
>
> **Anti-deferral rule:** no listed hard task moves to a later phase unless this file records the move and the reason.

## v0.1.0 - Scaffold (DONE, 2026-10-13)
- [x] Manifest, README, CHANGELOG, REPS, dual license, CI, deny, clippy, rustfmt, DIRECTIVES, ROADMAP, PLAN.

## v0.2.0 - Design lock
Exit: App, route declarations, Handler, Context, extractors, middleware, Render trait, and error model written in `docs/API.md` and approved.
- [ ] Template engine chosen for the first run (O-1).

## v0.3.0 - The thin slice
Exit: a site with login, forms, sessions, static files, and rendered pages runs on serve-net 0.3.0 behind Apache.
- [ ] Router with normalization, 404 and 405; route groups.
- [ ] Handlers and extractors (path, query, headers, cookies, form, JSON, session).
- [ ] Middleware with checkpoints; request id, access log, security headers, CSRF.
- [ ] Security adapters for every serve-net slot; startup declaration checks; `load_checked`.
- [ ] Static files; MIME; error pages; health endpoints; Render trait with one engine.

## v0.4.0 - Completeness
- [ ] CORS; content negotiation; redirects policy; compression layer (for direct mode).

## v0.9.0 - Hardening
- [ ] Attack tests for every threat in PLAN section 10; adversarial review; router at 10,000 routes.

## v1.0.0 - Stable
- [ ] Frozen after the first site has run on it end to end.
