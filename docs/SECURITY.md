# web-net - Security

> What web-net defends against, how, and where each defence is tested. The design and its reasons are in [`../dev/PLAN.md`](../dev/PLAN.md) sections 4, 6, 12, and 13.

## Reporting

Report a vulnerability privately through GitHub's security advisories on [jamesgober/web-net](https://github.com/jamesgober/web-net/security/advisories/new), not in a public issue.

## Threats and defences

Every row has an attack test in `tests/attacks.rs` (the id is the test's prefix) that must fail to exploit, and most have more tests in the other files.

| Id | Threat | Defence |
|---|---|---|
| T-1 | A spelling of a path (encoded letters, dot segments, empty segments, case, trailing slash, `;`, encoded separators) reaches a route around its gate | One normalization before routing: escapes decoded once and re-encoded one way, dot segments removed (never above the root), empty segments collapsed; `%2F`, `%5C` and raw `\`, controls (C0, DEL, and C1), and bytes that are not UTF-8 refused with 400. Any non-canonical path is redirected, never routed, so the router only ever sees canonical paths. Fuzzed: a canonical redirect is never redirected again, and no spelling reaches the protected page. |
| T-2 | A route is reachable because its access was forgotten | With a gate that has rules, every route declares `public()` or `allow(rule)`, or the application does not build; a group's rule holds for every route in it (a route's own rule adds to it, and a public route inside a group with a rule stops the build). With the `Open` gate there is no rule to forget. Handlers receive a `Context`, which only web-net makes, after the access check. A route the gate hides reads as missing for every method: the 405 and `OPTIONS` answers go only to someone who may use one of its methods. |
| T-3 | A forged `Host` (or absolute-form authority) reaches a site or a redirect; DNS rebinding | Unknown hosts get 421 (`OPTIONS *` and an empty `Host` included). A site with no declared host answers the development hosts only (`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`), so a name someone else points at the server is never the site; answering every host takes `any_host()`. Redirects to another host or to HTTPS use the declared canonical host only; `https_only` needs a declared host. |
| T-4 | An open redirect through a handler or a link | `Context::redirect` and `Context::url` take site-relative paths only (one leading `/`, never `//` or `/\`, visible ASCII); `Context::url_path` encodes each segment of a path built from input; `redirect_external` only to hosts from `redirect_hosts`, never with user information. |
| T-5 | Internal detail in an error reply; a panic that drops the connection | One error function: a generic title and message and a reference (a keyed value that reveals no counter), in HTML or JSON; codes and sources only to `Events`. A panic anywhere in the application's code on the request path (gate, checkpoint, readiness check, handler, hook, error template) is caught, answered with the built-in 500 page, and reported as `Panicked`; a panicking event sink loses its event, never the reply. Catching needs `panic = "unwind"` (the default): a build with `panic = "abort"` ends the process on the first panic. |
| T-6 | Half of a failed handler's reply leaves (a cookie set before the error) | The handler writes into a reply web-net holds; on an error or a panic it is discarded whole. |
| T-7 | Header injection or response splitting | Reply fields are checked as they are set (token names, no control characters); framing fields (`content-length`, `transfer-encoding`, `connection`, `keep-alive`, `upgrade`) are refused; a bad field turns the reply into a 500. At most 64 fields. |
| T-8 | Parameter pollution | A query name given twice is a 400 from `Context::query`. |
| T-9 | Cookie tossing | `Request::cookie` refuses a name given twice as ambiguous, across every `Cookie` field of the request: several fields are read as one (HTTP/2 and HTTP/3 split the cookie into crumbs, RFC 9113 section 8.2.3), so a name in two of them is refused like a name twice in one. |
| T-10 | Cross-site request forgery | Every unsafe method on a route that is not exempt (an exemption needs a reason) passes csrf-sec's origin policy and a token bound to the session, before any hook or handler runs: from `X-CSRF-Token` (exactly one) or the `csrf_token` field (a multipart body is read up to its first file part, where the token must have come). No binding, no unsafe request. |
| T-11 | Directory traversal in static files | The path is canonical before it reaches the folder; the resolved file must be inside the resolved root, so a symbolic link cannot lead out. |
| T-12 | Special files | Segments starting with a dot (unless allowed), containing `:` (alternate data streams, drive letters), ending in a dot or a space, or naming a Windows device (`COM1`, `COM¹`, `CON .txt`) are 404 on every platform, checked on the request's names and again on the resolved ones (a Windows 8.3 short name cannot reach a dot file). No directory listings. |
| T-13 | Protocol downgrade, framing, content sniffing | HSTS on HTTPS replies (never for development hosts), `X-Frame-Options: DENY` and `frame-ancestors 'none'`, a strict content security policy, `nosniff` on everything. |
| T-14 | Cross-origin reads | No CORS fields without a declared policy; `*` never with credentials (refused at build); `Vary: origin`. |
| T-15 | Resource exhaustion | serve-net's limits on the wire; in web-net, at most 256 path segments, 8 parameters per pattern, 64 reply fields, a page budget (8 MiB by default), per-route form limits, files over 1 MiB sent in parts, at most 16,384 large-file replies in progress per application (past it a new one is 503 with `Retry-After`; one in progress is never forgotten). |
| T-16 | A large-file download ends cleanly with the wrong bytes | Each reply in parts keeps a record from its first part to its last, or until serve-net reports the request done (`HttpService::done`, which a wrapper forwards); a record is never evicted. Every part reopens the file found for the first part and checks its length and modification time; a change, or a read that comes up short, ends the connection abortively. `tests/streams.rs` runs 300 dropped downloads past one in progress on one worker. |

Also defended, with tests elsewhere: personal pages in a shared cache (the `Guests` policy is private for signed-in visitors, a reply with a cookie is never public, and `App::respond` never marks a reply keepable when it sets a cookie, has the handler's own `Cache-Control`, or has a CORS policy: `tests/negotiation.rs`), compression side channels (compression is off by default; csrf-sec masks tokens per reply; any other secret on a compressed page beside reflected input stays exposed to BREACH, so pages that carry one leave compression off), and handlers that write HTML themselves (`escape_html`).

## Review

0.7 had an independent adversarial review of `src/`. It found seven defects, all fixed with regression tests before the release: a multipart CSRF token checked after the handler had run (now before), `public` caching of a reply with a cookie, a cacheability report that missed the handler's own `Cache-Control` and CORS fields, Windows short names reaching dot files, a failed file read leaving a broken reply, a preflight listing methods without a policy, and an empty `Host` passing the host check. Its lower-confidence notes (superscript device names, `CON .txt`, `/style.css/` under `TrailingSlash::Add`) were fixed too. Recorded as PLAN D-046 to D-050.

A second review, of the fixes and the code new in 0.7, found no CSRF bypass and four more defects, all fixed with regression tests (`tests/review.rs`): a large file changed between the parts of its reply could finish cleanly with the wrong bytes (now an abortive close); the gate's clearing cookie could cancel a session the handler had just set; a handler's own `public` cache header could go out beside a pre-session cookie (a login-CSRF vector through a shared cache); and health paths did not answer under `TrailingSlash::Add`. Preflights now run before the gate as the plan says. Recorded as PLAN D-051 to D-055.

An independent review of 0.9.0 found no CSRF bypass and no way out of the static folder (every traversal, encoding, Windows-name, and hidden-file probe failed). Its findings, all fixed in 0.10.0 with regression tests (`tests/review2.rs`, `tests/streams.rs`):

- a large-file download still in progress was forgotten after 256 later large-file replies on its worker and restarted from byte 0 mid-body, ending cleanly with the wrong bytes (T-16);
- panics outside the handler (gate, checkpoint, event sink, error template) were not caught, answered, or reported (T-5);
- static files resolved their path again on every request and every part (now cached, see `PERFORMANCE.md`);
- the method answers revealed routes the gate hides; any `Host` was accepted with none declared; an upper-case literal under `lowercase_paths` built and never matched; `Context::url` accepted `//evil`; compression dropped `accept-encoding` from a handler's own `Vary`; a checkpoint's deny status was not range-checked; a route's own rule replaced its group's instead of adding to it.

Recorded as PLAN D-072 to D-084.

## What web-net does not do

- **Escaping.** Contextual escaping of values in pages is the template engine's job (`Render`). web-net's own pages contain fixed text and the reference only; `escape_html` covers a handler that writes HTML itself.
- **Authentication and authorization decisions.** They belong to the application's `Gate`. web-net guarantees that the gate runs and that nothing reaches a handler without it.
- **Content inspection of uploads.** `Context::form_inspected` and `Context::upload_inspected` take an inspector for that.
- **Rate limits, bans, and admission.** serve-net and the layer in front of it.

## Verification

- `tests/attacks.rs`: one attack per threat; `tests/review2.rs` and `tests/streams.rs`: the 0.9.0 review's findings.
- Property tests (`src/url.rs`, `src/router.rs`): normalization is idempotent and never leaves a dot segment, an empty segment, a backslash, or a control; every spelling of a path normalizes to one canonical path; decoding inverts the canonical encoding; route lookup is sound and complete against the plain definition.
- Fuzz targets (`fuzz/`): `request` (any bytes as requests on a keep-alive connection) and `path` (any request target, with the no-redirect-loop and no-bypass invariants).
- `tests/alloc.rs`: the warm request path allocates nothing.
