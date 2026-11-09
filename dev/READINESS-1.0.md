# web-net - Readiness for 1.0

> For James. 1.0 freezes the API until 2.0, and a crates.io release cannot be taken back, so 1.0 is your decision. This note says what is done, what is not, and what needs you. Written at 0.9.0 (2026-11-09).

## Recommendation

**Not yet.** The code, the tests, and the review are where a 1.0 should be. What is missing is use: no site has run on web-net in production, and DIRECTIVES section 3 item 10 makes that a condition of 1.0. Keep releasing 0.9.x until a site has run on it for two weeks, then decide.

## Done

| Area | State |
|---|---|
| Request path | site, canonical URL, early (files, health), authenticate, route, method, authorize, checkpoint, CSRF, hooks, handler, render, finish; every step tested in memory and over a socket (`examples/hello.rs`, `examples/site.rs`) |
| Security | every threat in PLAN section 13 has an attack test (`tests/attacks.rs`, T-1 to T-15); property tests for paths and lookup; two fuzz targets; an independent adversarial review in 0.7 with all seven findings fixed test-first; `docs/SECURITY.md` |
| Performance | no allocation per warm request (counted); lookup flat from 10 to 10,000 routes; about 0.7 µs of web-net's own work per request on a loaded machine (`docs/PERFORMANCE.md`) |
| Integrations | gatekeeper-io's `Gate` builds an `App` unchanged; Luminess renders pages through `Cx::body_mut`; form-net's alpha routes run with csrf-sec; serve-net 0.7 underneath |
| API | `docs/API.md`; reported structs and growing enums are `#[non_exhaustive]`; zero third-party runtime dependencies; MSRV 1.85; CI on Linux, macOS, Windows, stable and 1.85 |

## Not done, and why

| Item | Why | What closes it |
|---|---|---|
| A production site on web-net | the platform it serves is not deployed | you deploy it; two weeks without a web-net defect |
| gatekeeper-io from crates.io | its repositories and publishing are yours to approve | create the repositories; then web-net can test against the published gate |
| Benchmarks on a quiet machine | the shared machine stayed at load 80 on 32 threads through every release | a quiet hour on the reference box; the method is in `docs/PERFORMANCE.md` |
| The held reply's one copy | serve-net hands out no body buffer and cannot clear a reply's fields | a serve-net API (PLAN O-4); web-net's change is a few lines |
| Brotli for dynamic replies | compress-lib has no Brotli encoder | an encoder in compress-lib; static files already serve precompressed `.br` |
| Themed error pages through Luminess | Luminess compiles against its own typed views, not web-net's `View` | either Luminess implements `Render`, or web-net grows an error-page hook a typed engine can fill (a 1.x addition either way) |

## Decisions that need you

1. **1.0 itself**, after the production run.
2. **Repositories for the gate crates**, so web-net's tests can use the real gate.
3. Nothing else blocks: every technical question in PLAN section 18 is answered or recorded with a recommendation.

## What 1.0 would freeze

The public items in `docs/API.md`. The parts most likely to want a change after real use, so worth a look before freezing: the `Gate` trait's shape (one trait, two checkpoints, `Rule` as an associated type), `Cx` writing into a held reply, and `Render`/`View` (only test engines and the example implement them so far).
