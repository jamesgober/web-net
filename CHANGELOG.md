<h1 align="center">
    <img width="90px" height="auto" src="https://raw.githubusercontent.com/jamesgober/jamesgober/main/media/icons/hexagon-3.svg" alt="Triple Hexagon">
    <br><b>CHANGELOG</b>
</h1>
<p>
  All notable changes to <code>web-net</code> will be documented in this file. The format is based on <a href="https://keepachangelog.com/en/1.1.0/">Keep a Changelog</a>,
  and this project adheres to <a href="https://semver.org/spec/v2.0.0.html/">Semantic Versioning</a>.
</p>

---

## [Unreleased]

---

## [0.6.0] - 2026-11-08

Performance.

### Added

- `benches/web.rs` (criterion): web-net against bare serve-net, 10,000
  routes, redirects, 404s, with and without security headers.
  `docs/PERFORMANCE.md` with the method and the numbers.
- `tests/alloc.rs`: the warm request path allocates nothing (counted).
- `tests/scale.rs`: 10,000 routes.

### Changed

- Host checks compare case-insensitively instead of copying the host per
  request; `Cache-Control` values are made at build; `Accept` is parsed only
  when it names JSON. No behaviour change.

---

## [0.5.0] - 2026-11-08

Negotiation, CORS, compression, caching, and several sites.

### Added

- Error replies in JSON when `Accept` prefers `application/json`.
  `Cx::language` and `Cx::media`.
- `Cors` on routes and groups: preflights answered before the gate, reply
  fields for allowed origins, `Vary: origin`; checked at build.
- `Builder::compress(Compression)`: gzip through compress-lib.
- `CachePolicy` on routes and groups (`NoStore`, `Private`, `Public`,
  `Guests`). `App::serve` returning `Served { outcome, route, cache }` with
  `Cacheable`.
- `Sites`: several applications chosen by host and base path.
- `Hook::BeforeRender`.

### Dependencies

- compress-lib 0.9 added.

---

## [0.4.0] - 2026-11-08

Actions: forms, uploads, and CSRF.

### Added

- CSRF on every unsafe method (`POST`, `PUT`, `PATCH`, `DELETE`) through
  csrf-sec: `Builder::csrf(Csrf)`; the identity's `csrf_binding`; the origin
  policy; a token from `X-CSRF-Token` or the `csrf_token` form field
  (urlencoded checked before the handler, multipart in the form pass, the raw
  body locked until then). `Route::csrf_exempt(reason)`. `Cx::csrf_token`.
- `Cx::form`, `Cx::form_inspected` (form-net typed forms with the route's
  limits), `Cx::upload` and `Cx::upload_inspected` (feature `uploads`),
  `Route::form_limits`. `From<form_net::FormError> for Error`.
- `Builder::redirect_hosts` and `Cx::redirect_external`.
- `Cx::precondition` (`If-Match`, `If-Unmodified-Since`, 412).
- Re-exports `web_net::form_net` and `web_net::csrf_sec`.
- Feature `uploads`.

### Changed

- An application with a route that takes an unsafe method now needs
  `Builder::csrf(..)`, or the route needs `csrf_exempt(reason)`; the build
  says which. `Cx::body` refuses an unverified multipart body.

### Dependencies

- form-net 0.9 and csrf-sec 0.9.3 added.

---

## [0.3.0] - 2026-11-08

Static files and the finish step.

### Added

- `Assets` and `Builder::assets`: a folder served under a mount before the
  gate and the router. Segments that file systems read specially are refused
  on every platform (dot files, `:`, a trailing dot or space, `\`, Windows
  device names); the resolved path must stay under the resolved root, so a
  symbolic link cannot lead out. No listings; `index` file per mount.
  Strong `ETag` and `Last-Modified`; `If-None-Match` and `If-Modified-Since`
  answer 304; one byte range (206, 416), `If-Range`; precompressed `.br` and
  `.gz` variants with `Vary`; `Cache-Control` per mount; files over 1 MiB sent
  in 64 KiB parts. `mime_for`, `INLINE_LIMIT`.
- `Builder::health` and `Builder::ready`: liveness and readiness paths
  before the gate.
- `SecurityHeaders` and `Builder::security_headers`: CSP, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and
  HSTS (HTTPS only, never for development hosts) on every reply, unless the
  handler set the field. `DEFAULT_CSP`.
- `Cx::set_cookie` (cookie-net `SetCookie`; `web_net::cookie_net`
  re-exported) and `Cx::not_modified` (ETag and 304 for pages).

### Changed

- Every reply web-net sends now carries the default security headers. Use
  `SecurityHeaders::none()` for the 0.2 behaviour.

### Dependencies

- parse-net 0.9.2 added.

---

## [0.2.0] - 2026-11-08

The core: a site answers real requests on serve-net. The plan is revised to
the newer design (hooks instead of middleware, one gate trait, typed views
for rendering); see `dev/PLAN.md` D-005 to D-020.

### Added

- `App` and `Builder`: hosts, aliases (redirected), 421 for unknown hosts,
  development hosts, HTTPS redirect, a base path for a site in a folder,
  trailing-slash policy, lower-case paths. `App` is a `serve_net::HttpService`;
  `respond`, `respond_identified` (for a caller that authenticated already),
  and `classify` (route and work class before admission).
- URL normalization: percent-escapes decoded once and re-encoded one way,
  dot segments removed (never above the root), empty segments collapsed;
  `%2F`, backslashes, control characters, and bytes that are not UTF-8
  refused with 400; non-canonical paths redirected (301, 308 for unsafe
  methods).
- Router: a segment trie compiled at build time, literal then parameter then
  wildcard with backtracking, no allocation per lookup; 404; 405 with `Allow`;
  `HEAD` from `GET`; automatic `OPTIONS` (and `OPTIONS *`); 501 for unknown
  methods.
- Gates: `Identity`, `Gate` (authenticate and authorize), `Denial`, `Open`,
  `Guest`. Every route declares `public()` or `allow(rule)` or the build
  fails; handlers get a `Cx` only after the access check. Sign-in redirect
  (303 with `next`) or 401 with a challenge. `Request::cookie` refuses
  ambiguous cookies.
- `Route`, `Group`, `get`/`post`/`put`/`patch`/`delete`, `Handler`.
- `Cx`: parameters (`param`, `param_as`), query (repeated names refused),
  body, status, checked reply fields, `html`, `text`, `url`, local-only
  `see_other` and `redirect`, `render` and `render_named`. The reply is held
  until the handler returns and discarded on an error or a panic.
- Hooks `Routed` and `Finish`, selected by `Routes::all`, `prefix`, `named`.
- Rendering: `Render`, `View`, `Shape`, `Key`, `ShapeId`, `Value`, `List`,
  `SafeHtml`, `Fields`, `Output` (with a page budget), `RenderError`,
  `TemplateId`. Route templates are resolved at build.
- Errors: `Error`, `Result`, `BuildError` (every problem at once),
  `Problem`; one error function with the engine's `error/<status>`
  template or a built-in page, and a request reference.
- `Events` (every refusal, denial, failure, panic, revocation) and
  `Checkpoint` at `Stage::Authorized` and `Stage::BeforeRender`.
- `examples/hello.rs`; `tests/pipeline.rs`; `docs/API.md`.

### Dependencies

- serve-net 0.7.1 (`http1`), cookie-net 0.7.1. No third-party runtime
  dependency.

---

## [0.1.0] - 2026-10-13

The scaffold and the plan. No functional code yet.

### Added

- Crate manifest (edition 2024, MSRV 1.85, no dependencies), `Apache-2.0 OR MIT`
  license, README, REPS, CI (Linux, macOS, Windows on stable and 1.85; audit
  and deny), `deny.toml`, `clippy.toml`, `rustfmt.toml`, `.gitattributes`.
- `dev/PLAN.md` (purpose, scope, architecture, threats, ecosystem, open
  decisions, decision log), `dev/DIRECTIVES.md`, and `dev/ROADMAP.md`.

[Unreleased]: https://github.com/jamesgober/web-net/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/jamesgober/web-net/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/jamesgober/web-net/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/jamesgober/web-net/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/jamesgober/web-net/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/jamesgober/web-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/web-net/releases/tag/v0.1.0
