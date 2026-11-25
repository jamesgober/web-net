<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>web-net</b>
    <br>
    <sub>
        <sup>THE WEB LAYER</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/web-net"><img src="https://img.shields.io/crates/v/web-net.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/web-net" alt="Download"><img alt="Crates.io Downloads" src="https://img.shields.io/crates/d/web-net?color=%230099ff"></a>
    <a href="https://docs.rs/web-net"><img src="https://docs.rs/web-net/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/web-net/actions"><img alt="GitHub CI" src="https://github.com/jamesgober/web-net/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg" alt="License"></a>
</p>

<p align="center">
    <b>Routes, gates, forms, files, and pages on serve-net.</b>
    <br>
    <i>A site in five lines, with the security rules built into the API.</i>
</p>

<br>

<p>
    <strong>web-net</strong> is the web layer on serve-net: what a site is written in. It takes a request from the server, decides which site and route it is for, checks who is asking and whether they may, runs the handler, renders the page, and answers every refusal and error the same way. It never sees a socket, a listener, or which front end the request came through.
</p>

<p>
    Security is part of the shape of the API. With a gate that has rules, every route declares its access or the application does not build. A handler only ever receives a request that passed its gate. Two spellings of a path can never reach different routes, and a failed handler never sends half a reply.
</p>

<p>
    It is synchronous and small: a trie compiled at build, a reply held until the handler returns, buffers reused per thread, and nothing allocated on a warm request. Template engines plug in through one trait, gates through another, and the crates it builds on (cookie-net, form-net, csrf-sec, parse-net) are all first-party.
</p>

---

## Features

### **Routing**
- **One canonical path** - every path is decoded once and redirected to its one spelling before routing, so encodings, dot segments, and slashes never reach a route around its gate.
- **A compiled trie** - literals, `:params`, and one `*rest` per pattern; lookup does not grow with the number of routes.
- **Methods** - `HEAD` follows `GET`, `OPTIONS` is automatic, and other methods get 405 with `Allow`.
- **Sites** - hosts, aliases, a base folder, trailing-slash policy, HTTPS redirects, and several sites in one table.

### **Gates and handlers**
- **One gate trait** - `authenticate` and `authorize`; every route declares `.public()` or `.allow(rule)`, and a group's rule holds for every route in it.
- **Writers that end a handler** - `cx.html`, `cx.text`, `cx.bytes`, `cx.redirect`, and `cx.render` return `Result`, so `?` gives the right error page.
- **Hooks instead of middleware** - before the handler, after it, and before rendering, for the routes they select.

### **Built in**
- **Forms and uploads** through form-net, **CSRF** through csrf-sec on every unsafe method, **cookies** through cookie-net.
- **Static files** with entity tags, 304, ranges, precompressed variants, and no way out of the folder.
- **Security headers** by default, **CORS** per route or group, **gzip**, **cache policies** with a report a cache in front can trust.
- **Events and checkpoints** - every refusal, denial, failure, and panic reported; in-flight revocation at web-net's stages.

### **Reliability and safety**
- **No unsafe code** - `#![forbid(unsafe_code)]`.
- **Panics answered** - a panic in a gate, handler, hook, or checkpoint is caught and answered with a 500; one in the error template falls back to the built-in page.
- **Tested against attacks** - an attack test per threat in `docs/SECURITY.md`, property tests for paths and lookup, and two fuzz targets.

---

## **Why web-net?**

### **The common case is short**
A site with a page and a parameter route is five lines, served with `App::listen`, with no builder to learn first.

### **Forgetting a check fails the build**
With a gate that has rules, a route without `.public()` or `.allow(rule)` is a build error, and an unsafe method without CSRF protection or a stated exemption is too.

### **One answer for every error**
Refusals, denials, handler errors, and panics all go through one function: the engine's error page or a built-in one, a reference the visitor can quote, and the cause only in the events.

### **Plugs in, does not take over**
Template engines implement `Render`, gates implement `Gate`, and a gateway in front calls `App::respond` with an identity it established. web-net depends on none of them.

---

<br>

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
web-net = "0.11"

# Multipart uploads to temporary files:
web-net = { version = "0.11", features = ["uploads"] }
```

**Feature recommendations**:
- **Most sites**: the default features.
- **File uploads**: `uploads` (form-net's file store).
- **TLS, several listeners, or custom limits**: add `serve-net = "0.9"` and serve the app with `serve_net::Server::builder()`.

---

<br>

## Quick Start

```rust,no_run
use web_net::{App, get};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    App::builder()
        .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
        .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
        .build()?
        .listen("127.0.0.1:8080")?
        .wait();
    Ok(())
}
```

A handler ends with one reply: `cx.html`, `cx.text`, `cx.bytes`, `cx.redirect`, or `cx.render` for a template. `?` turns any error into the right error page.

With no host declared, the site answers `localhost` (and `127.0.0.1`, `[::1]`, `*.localhost`) only, so it works on a laptop as it is and a name someone else points at the server is never the site. Declare the real host before deploying (`.host("example.com")`), or `.any_host()` behind a front that checked it.

### **A site with a host, a folder, and a form**

```rust,no_run
use web_net::{App, Route, get};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::builder()
        .host("example.com")
        .alias("www.example.com")
        .base("/blog")
        .route(get("/", |cx| cx.html(200, "<h1>Blog</h1>")))
        .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
        .route(Route::at("/contact")
            .get(|cx| cx.html(200, "<form method=post></form>"))
            .post(|cx| cx.redirect(303, "/"))
            // Unsafe methods need Builder::csrf(..) or an exemption with a reason.
            .csrf_exempt("demo: the POST changes nothing"))
        .build()?;

    app.listen("127.0.0.1:8080")?.wait();
    Ok(())
}
```

### **The request path**

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

### **Plugging in**

- **Authentication and authorization**: implement `Gate` (`authenticate`, `authorize`) and `Identity`, then `App::with_gate(gate)`. A front layer that authenticates on its own passes the identity to `App::respond` and forwards serve-net's `done` to the app.
- **Templates**: implement `Render`. A typed engine compiles against your own types (`type View<'a> = Page<'a>`); a dynamic one reads any `View`. Set it with `App::builder().render(engine)`.
- **Detection and logs**: implement `Events` (every refusal, denial, failure, panic) and `Checkpoint` (in-flight revocation).

---

## **Status: Beta**

**Current Version:** `0.11.0`, beta.
**Target:** `1.0.0`, after a site has run on web-net in production (`dev/READINESS-1.0.md`).

**What's complete**:
- **Routing, sites, and canonical paths** - one spelling per path, hosts, aliases, folders, HTTPS.
- **Gates, hooks, and handlers** - access declared per route and group, CSRF on every unsafe method.
- **Forms, uploads, cookies, files** - through form-net, cookie-net, and the built-in static file server.
- **Rendering and errors** - the `Render` trait, error pages from the engine or built in, events for every outcome.
- **HTTP/1.1 and HTTP/2** - over serve-net 0.9; over HTTP/2, static files up to 16 MiB go whole until serve-net can send a reply in parts there.

**What's planned before 1.0**:
- A site in production on web-net for two weeks.
- Large files over HTTP/2 in parts, and a `Content-Length` on large files, once serve-net offers both.
- Benchmarks on a quiet machine.

**Performance**: the warm request path allocates nothing, and web-net adds about a microsecond of its own work per request with the default security headers. Figures and method in `docs/PERFORMANCE.md`; they were taken on a shared machine and are fit for comparing cases, not as absolute numbers.

**Note on API stability**: the API is pre-1.0 and may change between minor versions; every change is in `CHANGELOG.md` with a migration note.

---

## **Documentation & Resources**

### **Documentation**
- **[Documentation Index](docs/README.md)** - where each document is
- **[API Reference](docs/API.md)** - every public item, with examples that compile
- **[Security](docs/SECURITY.md)** - the threats and the defence against each
- **[Performance](docs/PERFORMANCE.md)** - method and figures

### **External Resources**
- **[API Documentation](https://docs.rs/web-net)** - the rustdoc
- **[Crate Registry](https://crates.io/crates/web-net)** - releases
- **[Examples Directory](examples/)** - `hello` and `site`
- **[Benchmarks](benches/)** - request and static file cases

### **Getting Started Guides**
- **[A small site](examples/hello.rs)** - pages, a parameter, a form, `listen`
- **[A site with sign-in](examples/site.rs)** - sessions, CSRF, an upload, static files, and pages rendered by Luminess

### **Common Use Cases**
- **A content site**: routes, `Assets`, a `Render` engine, `CachePolicy::Guests`.
- **A signed-in application**: a `Gate`, `.allow(rule)` per route or group, `Builder::csrf`, `Context::form`.
- **Behind a gateway**: `App::respond` with the gateway's identity, `HttpService::done` forwarded, `Sites` for several apps.

---

### **Troubleshooting**

<details>
  <summary><b>Every request gets 421 Misdirected Request?</b></summary>
    <p>With no host declared, a site answers only <code>localhost</code>, <code>127.0.0.1</code>, <code>[::1]</code>, and <code>*.localhost</code>. Add <code>.host("example.com")</code> for the real name, or <code>.any_host()</code> when a front checks the host.</p>
</details>

<details>
  <summary><b>The build says a route declares no access?</b></summary>
    <p>With a gate that has rules, every route says <code>.public()</code> or <code>.allow(rule)</code>, or sits in a group that does. A public route cannot sit inside a group with a rule: move it out of the group.</p>
</details>

<details>
  <summary><b>The build says an unsafe method needs CSRF protection?</b></summary>
    <p>Set <code>Builder::csrf(Csrf::new(key)?)</code>, and give your identities a <code>csrf_binding</code>, or mark the route <code>.csrf_exempt("reason")</code>.</p>
</details>

<details>
  <summary><b>A closure cannot read fields of my identity type?</b></summary>
    <p>Type its parameter: <code>|cx: &amp;mut Context&lt;'_, User&gt;|</code>. Rust checks the closure before the builder fixes the type; named functions need nothing extra.</p>
</details>

---

### **Version Compatibility**
- **Rust**: 1.85+ (edition 2024)
- **Edition**: 2024
- **MSRV Policy**: once `v1.0.0` ships, the MSRV stays within the last 12 stable Rust releases
- **API Stability**: pre-1.0; minor versions may break, each with a migration note
- **serve-net**: 0.9; code that names serve-net types beside web-net uses the same version

### **Development Setup**
```bash
git clone https://github.com/jamesgober/web-net.git
cd web-net
cargo test --all-features
cargo bench
cargo clippy --all-targets --all-features -- -D warnings
```

## **Contributing**

See [`dev/DIRECTIVES.md`](dev/DIRECTIVES.md) for the engineering standards and the definition of done. Before a pull request, `cargo fmt --all`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --all-features` must be clean.

<hr>

<div id="license">
    <h2>License</h2>
    <p><b>web-net</b> is dual-licensed under either of:</p>
    <ul>
        <li><b>Apache License, Version 2.0</b>, see <a href="./LICENSE-APACHE" title="Apache-2.0 License">LICENSE-APACHE</a> or <a href="http://www.apache.org/licenses/LICENSE-2.0" title="Apache-2.0 License" target="_blank">apache.org/licenses/LICENSE-2.0</a></li>
        <li><b>MIT License</b>, see <a href="./LICENSE-MIT" title="MIT License">LICENSE-MIT</a> or <a href="https://opensource.org/licenses/MIT" title="MIT License" target="_blank">opensource.org/licenses/MIT</a></li>
    </ul>
    <p>at your option.</p>
    <h3>Contribution</h3>
    <p>Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in <b>web-net</b> by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.</p>
    <p>Unless required by applicable law or agreed to in writing, software distributed under the Licenses is distributed on an <b>"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND</b>, either express or implied.</p>
</div>

<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
