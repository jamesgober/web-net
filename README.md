<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>web-net</b>
    <br>
    <sub><sup>THE WEB LAYER</sup></sub>
</h1>

<div align="center">
    <a href="https://crates.io/crates/web-net"><img alt="Crates.io" src="https://img.shields.io/crates/v/web-net"></a>
    <a href="https://crates.io/crates/web-net"><img alt="Downloads" src="https://img.shields.io/crates/d/web-net?color=%230099ff"></a>
    <a href="https://docs.rs/web-net"><img alt="docs.rs" src="https://img.shields.io/docsrs/web-net"></a>
    <a href="https://github.com/jamesgober/web-net/actions"><img alt="CI" src="https://github.com/jamesgober/web-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</div>

<br>

<div align="left">
    <p>
        <strong>web-net</strong> is the web layer on serve-net: what a site is written in. It takes a request from the server, decides which site and route it is for, checks who is asking and whether they may, runs the handler, renders the page, and answers every refusal and error the same way. It never sees a socket, a listener, or which front end the request came through.
    </p>
    <p>
        Security is part of the shape of the API: every route declares its access or the application does not build, a handler only ever receives a request that passed its gate, two spellings of a path can never reach different routes, and a failed handler never sends half a reply.
    </p>
    <br>
    <hr>
    <p>
        <strong>MSRV is 1.85+</strong> (Rust 2024 edition). <code>#![forbid(unsafe_code)]</code>. No third-party runtime dependencies.
    </p>
    <blockquote>
        <strong>Status: <code>0.8.0</code>, alpha.</strong> The API is pre-1.0 and may change between minor versions. The design is in <a href="./dev/PLAN.md"><code>dev/PLAN.md</code></a>, the schedule in <a href="./dev/ROADMAP.md"><code>dev/ROADMAP.md</code></a>, the reference in <a href="./docs/API.md"><code>docs/API.md</code></a>.
    </blockquote>
</div>

<hr>
<br>

## Quick start

```toml
[dependencies]
web-net = "0.8"
serve-net = "0.7"
```

```rust
use web_net::{App, Route, get};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::builder()
        .host("example.com")
        .alias("www.example.com")
        .base("/blog")
        .route(get("/", |cx| { cx.html(200, "<h1>Blog</h1>"); Ok(()) }).public())
        .route(get("/posts/:slug", |cx| {
            let slug = cx.param("slug").unwrap_or_default();
            cx.text(200, &slug);
            Ok(())
        }).public())
        .route(Route::at("/contact")
            .get(|cx| { cx.html(200, "<form method=post></form>"); Ok(()) })
            .post(|cx| cx.see_other("/"))
            .public()
            // Unsafe methods need Builder::csrf(..) or an exemption with a reason.
            .csrf_exempt("demo: the POST changes nothing"))
        .build()?;

    serve_net::Server::builder()
        .listener(serve_net::ListenerSpec::tcp("web", "127.0.0.1:8080"))
        .serve(app)?
        .wait();
    Ok(())
}
```

## The request path

| Step | What happens | Answers |
|---|---|---|
| site | the host picks the site; the base path is removed | 421 unknown host; 301 alias or HTTPS |
| url | decoded once, one canonical spelling, dot and empty segments removed | 400 refused; 301/308 to the canonical path |
| authenticate | the gate says who is asking | the gate's denial |
| route | a trie compiled at build | 404 |
| method | `HEAD` from `GET`, `OPTIONS` automatic | 405 with `Allow`, 501 |
| authorize | the route's rule, unless it is public | 303 to sign-in, 401, 403, 404 |
| hooks, handler | only the hooks registered for the route | the handler's error |
| render | the engine reads a typed view; no JSON | 500 |
| errors | one function: the engine's error template or a built-in page | |

## Plugging in

- **Authentication and authorization**: implement `Gate` (`authenticate`, `authorize`) and `Identity`. `App::with_gate(gate)`. A front layer that authenticates on its own calls `App::respond_identified`.
- **Templates**: implement `Render` and read values through `View`. Engines live in their own crates; web-net depends on none.
- **Detection and logs**: implement `Events` (every refusal, denial, failure, panic) and `Checkpoint` (in-flight revocation).

Built in: static files (`Assets`: validators, ranges, precompressed variants, no escape from the folder), health and readiness paths, strict security headers by default (`SecurityHeaders`), cookies out through cookie-net, and a 304 fast path for pages (`Cx::not_modified`).

Forms and uploads through form-net (`Cx::form`, `Cx::upload`), CSRF through csrf-sec on every unsafe method (origin policy and a session-bound token; a route without either does not build unless it is exempt with a reason), allowlisted external redirects, and `If-Match` preconditions.

Negotiation (JSON error replies, `Cx::language`), CORS per route or group, gzip compression, cache policies with a report a cache in front can trust (`App::serve`), and several sites in one table (`Sites`).

Performance: the warm request path allocates nothing, route lookup does not grow with the number of routes, and web-net adds well under a microsecond of its own work per request (`docs/PERFORMANCE.md`).

Security: every threat the plan names has an attack test that must fail, the path rules have property tests, whole requests are fuzzed, and `docs/SECURITY.md` lists each defence.

`examples/site.rs` puts it together: sessions, sign-in with CSRF, an upload, static files, and pages rendered by Luminess.

Coming next (see the roadmap): the beta polish pass (0.9).

<hr>
<br>

## Contributing

See <a href="./dev/DIRECTIVES.md"><code>dev/DIRECTIVES.md</code></a> for engineering standards and the definition of done. Before a PR: `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<br>

<div id="license">
    <h2>License</h2>
    <p>Licensed under either of</p>
    <ul>
        <li><b>Apache License, Version 2.0</b> - <a href="./LICENSE-APACHE">LICENSE-APACHE</a></li>
        <li><b>MIT License</b> - <a href="./LICENSE-MIT">LICENSE-MIT</a></li>
    </ul>
    <p>at your option.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>James Gober.</strong></sup>
</div>
