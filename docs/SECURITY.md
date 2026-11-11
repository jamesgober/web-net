# web-net - Security

> What web-net defends against, how, and where each defence is tested. The design and its reasons are in [`../dev/PLAN.md`](../dev/PLAN.md) sections 4, 6, 12, and 13.

## Reporting

Report a vulnerability privately through GitHub's security advisories on [jamesgober/web-net](https://github.com/jamesgober/web-net/security/advisories/new), not in a public issue.

## Threats and defences

Every row has an attack test in `tests/attacks.rs` (the id is the test's prefix) that must fail to exploit, and most have more tests in the other files.

| Id | Threat | Defence |
|---|---|---|
| T-1 | A spelling of a path (encoded letters, dot segments, empty segments, case, trailing slash, `;`, encoded separators) reaches a route around its gate | One normalization before routing: escapes decoded once and re-encoded one way, dot segments removed (never above the root), empty segments collapsed; `%2F`, `%5C` and raw `\`, controls, and bytes that are not UTF-8 refused with 400. Any non-canonical path is redirected, never routed, so the router only ever sees canonical paths. Fuzzed: a canonical redirect is never redirected again, and no spelling reaches the protected page. |
| T-2 | A route is reachable because its access was forgotten | Every route declares `public()` or `allow(rule)`, or the application does not build. Handlers receive a `Cx`, which only web-net makes, after the access check. |
| T-3 | A forged `Host` (or absolute-form authority) reaches a site or a redirect | Unknown hosts get 421 (`OPTIONS *` and an empty `Host` included); redirects to another host or to HTTPS use the declared canonical host only; `https_only` needs a declared host. |
| T-4 | An open redirect through a handler | `Cx::redirect` takes site-relative paths only (one leading `/`, never `//` or `/\`, visible ASCII); `redirect_external` only to hosts from `redirect_hosts`, never with user information. |
| T-5 | Internal detail in an error reply | One error function: a generic title and message and a reference, in HTML or JSON; codes and sources only to `Events`. Panics are caught and answered with the same page. |
| T-6 | Half of a failed handler's reply leaves (a cookie set before the error) | The handler writes into a reply web-net holds; on an error or a panic it is discarded whole. |
| T-7 | Header injection or response splitting | Reply fields are checked as they are set (token names, no control characters); framing fields (`content-length`, `transfer-encoding`, `connection`, `keep-alive`, `upgrade`) are refused; a bad field turns the reply into a 500. At most 64 fields. |
| T-8 | Parameter pollution | A query name given twice is a 400 from `Cx::query`. |
| T-9 | Cookie tossing | `Request::cookie` refuses a name given twice, and a request with two `Cookie` fields, as ambiguous. |
| T-10 | Cross-site request forgery | Every unsafe method on a route that is not exempt (an exemption needs a reason) passes csrf-sec's origin policy and a token bound to the session, before any hook or handler runs: from `X-CSRF-Token` (exactly one) or the `csrf_token` field (a multipart body is read up to its first file part, where the token must have come). No binding, no unsafe request. |
| T-11 | Directory traversal in static files | The path is canonical before it reaches the folder; the resolved file must be inside the resolved root, so a symbolic link cannot lead out. |
| T-12 | Special files | Segments starting with a dot (unless allowed), containing `:` (alternate data streams, drive letters), ending in a dot or a space, or naming a Windows device (`COM1`, `COM¹`, `CON .txt`) are 404 on every platform, checked on the request's names and again on the resolved ones (a Windows 8.3 short name cannot reach a dot file). No directory listings. |
| T-13 | Protocol downgrade, framing, content sniffing | HSTS on HTTPS replies (never for development hosts), `X-Frame-Options: DENY` and `frame-ancestors 'none'`, a strict content security policy, `nosniff` on everything. |
| T-14 | Cross-origin reads | No CORS fields without a declared policy; `*` never with credentials (refused at build); `Vary: origin`. |
| T-15 | Resource exhaustion | serve-net's limits on the wire; in web-net, at most 256 path segments, 8 parameters per pattern, 64 reply fields, a page budget (8 MiB by default), per-route form limits, files over 1 MiB sent in parts. |

Also defended, with tests elsewhere: personal pages in a shared cache (the `Guests` policy is private for signed-in visitors, a reply with a cookie is never public, and `App::serve` never marks a reply keepable when it sets a cookie, has the handler's own `Cache-Control`, or has a CORS policy: `tests/negotiation.rs`), compression side channels (compression is off by default; csrf-sec masks tokens per reply).

## Review

0.7 had an independent adversarial review of `src/`. It found seven defects, all fixed with regression tests before the release: a multipart CSRF token checked after the handler had run (now before), `public` caching of a reply with a cookie, a cacheability report that missed the handler's own `Cache-Control` and CORS fields, Windows short names reaching dot files, a failed file read leaving a broken reply, a preflight listing methods without a policy, and an empty `Host` passing the host check. Its lower-confidence notes (superscript device names, `CON .txt`, `/style.css/` under `TrailingSlash::Add`) were fixed too. Recorded as PLAN D-046 to D-050.

A second review, of the fixes and the code new in 0.7, found no CSRF bypass and four more defects, all fixed with regression tests (`tests/review.rs`): a large file changed between the parts of its reply could finish cleanly with the wrong bytes (now an abortive close); the gate's clearing cookie could cancel a session the handler had just set; a handler's own `public` cache header could go out beside a pre-session cookie (a login-CSRF vector through a shared cache); and health paths did not answer under `TrailingSlash::Add`. Preflights now run before the gate as the plan says. Recorded as PLAN D-051 to D-055.

## What web-net does not do

- **Escaping.** Contextual escaping of values in pages is the template engine's job (`Render`). web-net's own pages contain fixed text and the reference only.
- **Authentication and authorization decisions.** They belong to the application's `Gate`. web-net guarantees that the gate runs and that nothing reaches a handler without it.
- **Content inspection of uploads.** `Cx::form_inspected` and `Cx::upload_inspected` take an inspector for that.
- **Rate limits, bans, and admission.** serve-net and the layer in front of it.

## Verification

- `tests/attacks.rs`: one attack per threat.
- Property tests (`src/url.rs`, `src/router.rs`): normalization is idempotent and never leaves a dot segment, an empty segment, a backslash, or a control; every spelling of a path normalizes to one canonical path; decoding inverts the canonical encoding; route lookup is sound and complete against the plain definition.
- Fuzz targets (`fuzz/`): `request` (any bytes as requests on a keep-alive connection) and `path` (any request target, with the no-redirect-loop and no-bypass invariants).
- `tests/alloc.rs`: the warm request path allocates nothing.
