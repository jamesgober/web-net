# Simplicity audit (0.9.0 to 0.10.0)

Written 2026-11-11, against the 0.9.0 public API. The test for each item:
can a newcomer write the common case in a line or two, read every name
without the docs, and find exactly one way to do it?

The 0.9 freeze does not protect an API that fails this test. Every fix below
ships in 0.10.0 with a migration note (`CHANGELOG.md`, `docs/release/v0.10.0.md`).

## The common case, before

A home page and a page per post, served on a port:

```rust,ignore
let app = App::builder()
    .route(get("/", |cx| { cx.html(200, "<h1>Blog</h1>"); Ok(()) }).public())
    .route(get("/posts/:slug", |cx| {
        let slug = cx.param("slug").unwrap_or_default();
        cx.text(200, &slug);
        Ok(())
    }).public())
    .build()?;
serve_net::Server::builder()
    .listener(serve_net::ListenerSpec::tcp("web", "127.0.0.1:8080"))
    .serve(app)?
    .wait();
```

Eleven lines, two crates, and three things a newcomer has to be told: why
`Ok(())` follows every reply, why `.public()` is needed on a site with no
sign-in at all, and why a parameter the pattern declares is an `Option`.

## The common case, after

```rust,ignore
App::builder()
    .route(get("/", |cx| cx.html(200, "<h1>Blog</h1>")))
    .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
    .build()?
    .listen("127.0.0.1:8080")?
    .wait();
```

## Findings

| # | Finding | Fix in 0.10 |
|---|---|---|
| S-1 | Serving an app needs serve-net's `Server::builder()`, a `ListenerSpec`, and a second dependency. | `App::listen(addr)` and `Sites::listen(addr)`: one TCP listener per resolved address, serve-net's defaults. `Server::builder().serve(app)` stays for everything else. |
| S-2 | Every reply writer returns `&mut Self`, so every handler ends with `; Ok(())`. | `Cx::html`, `Cx::text`, and `Cx::bytes` return `Result`: a handler that writes one reply is one expression. |
| S-3 | A site with the `Open` gate (no sign-in) has to write `.public()` on every route, when it has no other choice. | A gate whose `Rule` is `NoRule` has only public routes; undeclared routes are public there. Gates with rules still fail the build for a route that declares nothing. |
| S-4 | `Cx::param` returns `Option`, although the matched pattern always has the parameter: handlers wrote `.unwrap_or_default()`. | `Cx::param` returns `Result` (500 `route.no_param` for a name the pattern does not have, a bug in the handler). `param_as` unchanged. |
| S-5 | `Cx::body()` reads the request body, `Cx::body_mut()` is the reply's buffer, and `Cx::body_bytes()` writes the reply: three "body" names, two directions. | `body()` stays the request body. `body_bytes(&[u8])` becomes `bytes(status, content_type, &[u8]) -> Result`, like `html` and `text`. `body_mut()` becomes `reply_buffer()`. |
| S-6 | Two ways to answer a form with 303: `see_other(path)` and `redirect(303, path)`. "See other" is protocol vocabulary. | `see_other` is removed; `redirect(303, path)`. Every reply writer takes the status first. |
| S-7 | `Cx::media(offers)` does not say it reads `Accept`; `language` does not say which header. | `accept(offers)` and `accept_language(offers)`, the header names. |
| S-8 | Two ways to set the template engine: `App::with(gate, engine)` and `Builder::render(engine)`. | `App::with` is removed: `App::with_gate(gate).render(engine)` or `App::builder().render(engine)`. |
| S-9 | Three ways for a wrapper to run one request: `App::respond`, `App::respond_identified`, `App::serve(.., Option<who>, ..)`; the last is named like starting a server. | One method: `App::respond(req, env, who: Option<&Identity>, reply) -> Served`. `HttpService::call` is `respond(.., None, ..)`. `Sites::serve` becomes `Sites::respond`. |
| S-10 | `Denial::status(code, ..)` is a constructor while `Error::status()` is a getter; the denial's getter is `status_code()`. | `Denial::with_status(status, code)` constructs; `Denial::status()` reads, as on `Error`. |
| S-11 | `Builder::challenge` does not say what it sets. | `Builder::www_authenticate`, the field it sets. |
| S-12 | `Route::at(pattern)` but `Group::new(prefix)`. | `Group::at(prefix)`. |
| S-13 | `docs/API.md` listed signatures as pseudo-code that never compiled, so it could drift. | Rewritten as a task-oriented reference; every block compiles as a doctest, the README's too. |
| S-14 | An `Events` sink the application also reads (a counter) needed a hand-written impl on `&'static T`; the orphan rule ruled out `Arc<T>`. | `Events` and `Checkpoint` are implemented for `Arc<T>`: `.events(Arc::clone(&sink))`. |
| S-15 | An error page of a site installed in a folder could not link its stylesheet: `ErrorPage` had no base path, and only the router knew it. (Found by a gateway building a site under `/blog/`.) | `ErrorPage::base` (`""` or `/blog`) and `ErrorPage::url(path)`, as `Cx::url` for pages; `with_base` for an engine's tests. Additive: `ErrorPage` is `#[non_exhaustive]` and `ErrorPage::new` is unchanged. |
| S-16 | `Cx`, the type every handler names, is an abbreviation a newcomer has to decode. | `Context`. Closures keep the short variable name `cx`, as Rust code names a context. |

## Kept, with the reason

- **`get(path, f)` and `Route::at(path).get(f).post(g)`**: the free functions are the one-method case, `Route::at` the several-methods case; neither can express the other in one line.
- **`.public()` and `.allow(rule)` with a gate that has rules**: declaring access on every route is the security rule that a forgotten check fails the build, not the request.
- **`cx.render(&view)` and `cx.render_view(&dyn View)`**: the second exists only for engines whose view type is `dyn View`, where Rust cannot coerce the argument during inference. One per engine kind.
- **`param` and `param_as`**: text and parsed are different results (500 for a missing name, 404 for a value that does not parse).
- **The `Render` trait, `Output`, and the view types**: unchanged; `ErrorPage` only gained `base` and `url` (S-15). They passed the review (one trait, three methods, plain names), and Luminess implements them; any change goes through the coordinated 0.10 of both crates.
- **Tier 3 items** (`classify`, `RouteId`, `Checkpoint`, `Stage`, `Hook`, `Routes`, `form_inspected`, `precondition`, `WorkClass`): for gateways and policies, documented after the common case.
