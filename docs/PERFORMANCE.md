# web-net - Performance

> What web-net costs per request on top of serve-net, how it is measured, and what is still to measure.

## Method

`benches/web.rs` (criterion) sends the same kind of request on a keep-alive test connection from `serve_net::testing` (no sockets), 50 requests per connection, buffers warmed outside the timing. `serve_net_alone` is a bare serve-net handler writing the same body; every other case is the same request through web-net. The difference is web-net's own work: site and host, canonical path, route lookup, the gate (`Open`), the handler context, the held reply's copy, and the security headers.

Run it with:

```
cargo bench --bench web
```

## Allocation

`tests/alloc.rs` counts allocations with a global allocator over 80 warm requests on one connection, through a bare serve-net handler and through web-net (host matched case-insensitively, a base path, a parameter route, `Accept` and `Accept-Encoding` sent). Result: **0.00 allocations per request on both**. web-net's warm request path allocates nothing: host checks compare without lower-case copies, `Cache-Control` values are made at build, the reply buffers are reused per thread, and parameters are byte ranges into the path.

Paths that do allocate, all off the common path: a non-canonical path (the canonical string for its redirect), an error reply (its page and reference), CSRF on unsafe methods (the request's own origin, and the urlencoded form parsed for its token), compression (the compressed body), rendering through `Context::render_named` (whatever the engine does).

## Numbers

Taken 2026-11-08 on a machine shared with other build and fuzz jobs (Windows 11, 32 threads, load around 80 in WSL at the time). They are only fit for comparing cases with each other in one run; a quiet rerun is on the 0.9 list.

| Case (Windows, MSVC, stable 1.99) | Time per request |
|---|---|
| serve-net alone | 0.59 µs |
| web-net, 10 routes, default security headers | 1.61 µs |
| web-net, 10 routes, `SecurityHeaders::none()` | 1.26 µs |
| web-net, 10,000 routes | about the same as 10 routes, within the noise |
| web-net, a redirect to the canonical path | about the same as a page |
| web-net, a 404 page | about the same as a page |

Reading them: web-net adds about 0.7 µs of its own work per request, and the default security headers add about 0.35 µs more, nearly all of it serve-net writing and checking about 400 more bytes of fields. Lookup time does not grow with the number of routes: the trie visits one node per segment and branches only where a literal and a parameter share a position.

## Open

- A quiet rerun on Linux, with the per-step split (site, path, lookup, context, finish) the plan's cost table estimates.
- The held reply's one copy into serve-net (PLAN O-4): goes when serve-net hands out its body buffer.
