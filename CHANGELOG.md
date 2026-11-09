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

[Unreleased]: https://github.com/jamesgober/web-net/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/jamesgober/web-net/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/jamesgober/web-net/releases/tag/v0.1.0
