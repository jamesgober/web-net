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

## Static files

`benches/assets.rs` asks for a 10 KB file, the same with `Accept-Encoding: br, gzip` (no variant on disk), a 304 for it, and a 2 MiB file in parts, on a keep-alive test connection. It uses only the API that 0.9 and 0.10 share, so one file measured both, alternating which went first, in one job (2026-11-12, same shared machine; Linux under load 50 to 80, Windows with real-time antivirus and a build running beside it).

| Case | Linux 0.9.0 | Linux 0.10.0 | Windows 0.9.0 (best) | Windows 0.10.0 (best) |
|---|---|---|---|---|
| 10 KB file | 10.4 µs | 4.8 µs | 373 µs | 96 µs |
| 10 KB file, client accepts br | 11.5 µs | 5.1 µs | 638 µs | 131 µs |
| 304 | 5.6 µs | 3.2 µs | 368 µs | 346 µs |
| 2 MiB file | 715 µs | 448 µs | 13.5 ms | 3.0 ms |

Linux figures are medians of four rounds per side; Windows figures are the best of four, because its medians moved by up to twenty times between rounds. What changed in 0.10: a per-mount cache of resolutions (a hit is one metadata call that does not follow links, not two or three `canonicalize` calls), the bytes of files up to 64 KiB kept while their length and time hold (a hit opens no file), and large files read in 256 KiB parts into one reused buffer from the path found for the first part (0.9 resolved the path again for every 64 KiB part). The 304 left on Windows is nearly all the one metadata call, which the antivirus makes slow; a revalidation interval without any call per hit would trade the two-second change detection for it, and is not done.

Run it with:

```
cargo bench --bench assets
```

## Open

- A quiet rerun on Linux, with the per-step split (site, path, lookup, context, finish) the plan's cost table estimates.
- The held reply's one copy into serve-net (PLAN O-4): goes when serve-net hands out its body buffer.
- A file-backed body from serve-net (sendfile, TransmitFile) for large files, and a declared length so they carry `Content-Length` (PLAN O-9).
