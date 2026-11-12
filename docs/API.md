<h1 align="center">
        <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br><b>web-net</b><br>
    <sub><sup>API REFERENCE</sup></sub>
</h1>
<div align="center">
    <sup>
        <a href="../README.md" title="Project Home"><b>HOME</b></a>
        <span>&nbsp;│&nbsp;</span>
        <span>API</span>
        <span>&nbsp;│&nbsp;</span>
        <a href="./SECURITY.md" title="Security"><b>SECURITY</b></a>
        <span>&nbsp;│&nbsp;</span>
        <a href="./PERFORMANCE.md" title="Performance"><b>PERFORMANCE</b></a>
    </sup>
</div>
<br>

A task-oriented tour of the 0.10 API, with every public item. The rustdoc
on [docs.rs](https://docs.rs/web-net) has the same items one by one; every
example here is compiled and run as a doctest, so this page cannot drift
from the code. The design and its reasons are in
[`../dev/PLAN.md`](../dev/PLAN.md).

- [Setup](#setup)
- [A site in five lines](#a-site-in-five-lines)
- [Handlers: `Context`](#handlers-cx)
- [Routes and groups](#routes-and-groups)
- [The site: hosts, folder, URLs](#the-site-hosts-folder-urls)
- [Gates: who is asking, and may they](#gates-who-is-asking-and-may-they)
- [Forms, uploads, CSRF](#forms-uploads-csrf)
- [Templates](#templates)
- [Static files and health](#static-files-and-health)
- [Headers, caching, compression, CORS](#headers-caching-compression-cors)
- [Hooks](#hooks)
- [Events and checkpoints](#events-and-checkpoints)
- [Behind a front, and several sites](#behind-a-front-and-several-sites)
- [Errors](#errors)
- [Constants and re-exports](#constants-and-re-exports)
- [Examples in the repository](#examples-in-the-repository)

## Setup

```toml
[dependencies]
web-net = "0.10"
# For multipart uploads to temporary files:
# web-net = { version = "0.10", features = ["uploads"] }
```

web-net runs on serve-net. `App::listen` starts a server with serve-net's
defaults, so most sites need no other dependency; add `serve-net = "0.7"`
for TLS, several listeners, other limits, or `serve_net::testing` in tests.

## A site in five lines

```rust,no_run
use web_net::{App, get};

App::builder()
    .route(get("/", |cx| cx.html(200, "<h1>Hello</h1>")))
    .route(get("/posts/:slug", |cx| cx.text(200, &cx.param("slug")?)))
    .build()?
    .listen("127.0.0.1:8080")?
    .wait();
# Ok::<(), Box<dyn std::error::Error>>(())
```

- `App::builder()` starts an app with the `Open` gate: no sign-in, every
  route public.
- `get(pattern, handler)` is a route. A handler takes `&mut Context` and returns
  `web_net::Result`.
- `build()` checks everything at once and returns `BuildError` listing every
  problem.
- `App::listen(addr)` serves it: one TCP listener per address `addr`
  resolves to. `wait()` blocks until the server is told to stop.
- With no host declared, the site answers the development hosts only
  (`localhost`, `127.0.0.1`, `[::1]`, `*.localhost`), so a name someone else
  points at the server is never the site. Declare the real host before
  deploying (`.host("example.com")`), or `.any_host()`.

Testing needs no socket:

```rust
use web_net::{App, get};

let app = App::builder().route(get("/", |cx| cx.text(200, "hi"))).build()?;
let reply = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!((reply.status, reply.text()), (200, "hi"));
# Ok::<(), web_net::BuildError>(())
```

## Handlers: `Context`

A handler receives a `Context`: the request, who sent it, and the reply. There is
no public way to make one; web-net builds it only after the request passed
its route's access check. The reply is held until the handler returns; on an
error or a panic it is thrown away and the error page goes out instead.

```rust
use web_net::{App, Error, get};

let app = App::builder()
    .route(get("/users/:id", |cx| {
        let id: u64 = cx.param_as("id")?;           // 404 if not a number
        let tab = cx.query("tab")?.unwrap_or_default();
        if id == 0 {
            return Err(Error::not_found("user.none"));
        }
        cx.text(200, &format!("user {id}, tab {tab}"))
    }))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /users/7?tab=posts HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.text(), "user 7, tab posts");
# Ok::<(), web_net::BuildError>(())
```

Reading the request:

| Method | Returns |
|---|---|
| `param(name)` | `Result<Cow<str>>`: a route parameter, decoded; 500 `route.no_param` for a name the pattern does not have |
| `param_as::<T>(name)` | `Result<T>`: parsed; 404 `route.param` when it does not parse |
| `query(name)` | `Result<Option<Cow<str>>>`: decoded; 400 `query.duplicate` for a repeated name |
| `body()` | `Result<&[u8]>`: the raw request body |
| `form::<T>()`, `upload(&Store)` | see [Forms](#forms-uploads-csrf) |
| `header(name)` | `Option<&[u8]>`: the first value of a request field |
| `method()`, `path()` | the method; the canonical path inside the site |
| `identity()` | `&Identity`: who is asking, possibly a guest |
| `id()` | `RequestId`: the reference shown on error pages |
| `request()` | `&Request`: everything else (see [Behind a front](#behind-a-front-and-several-sites)) |
| `accept(offers)` | the best of `offers` for `Accept`, or `None` |
| `accept_language(offers)` | the best of `offers` for `Accept-Language`, or `None` |
| `next_path()` | `Result<Option<String>>`: the `next` a sign-in redirect carried, only when it is a path of this site |
| `url(path)` | `Result<String>`: a site path with the base path in front, for links; 500 `url.not_local` for anything else (`//host`, `https://..`) |
| `url_path(&[segments])` | `String`: a link from segments, each encoded (`["tags", tag]`), for paths built from input |

Writing the reply. Each of the first five is a whole reply and returns
`Result`, so a handler ends with it:

| Method | Reply |
|---|---|
| `html(status, &str)` | `text/html; charset=utf-8` |
| `text(status, &str)` | `text/plain; charset=utf-8` |
| `bytes(status, content_type, &[u8])` | any type |
| `redirect(status, path)` | 301, 302, 303, 307, 308 to a site path; 303 after a form |
| `render(&view)` | the route's template (see [Templates](#templates)) |
| `redirect_external(status, url)` | to a host listed with `Builder::redirect_hosts` only |
| `status(u16)` | the status for `render` and `reply_buffer` (default 200) |
| `set_header(name, value)` | a reply field; a bad one, or a framing field, turns the reply into a 500 |
| `set_cookie(&SetCookie)` | a `Set-Cookie` field, built with `cookie_net` |
| `reply_buffer()` | `&mut Vec<u8>`: the body, emptied, for a writer that appends |
| `not_modified(tag)` | sets `ETag`; `true` (and 304) when `If-None-Match` matches |
| `precondition(tag, modified)` | `Result`: 412 when `If-Match` or `If-Unmodified-Since` is false |
| `csrf_token()` | `Result<String>`: a token for the visitor's session |

```rust
use web_net::{App, get, cookie_net::SetCookie};

let app = App::builder()
    .route(get("/", |cx| {
        if cx.not_modified("rev-7") {
            return Ok(()); // 304, nothing built
        }
        let theme = SetCookie::new("theme", "dark").map_err(|_| web_net::Error::internal("cookie"))?;
        cx.set_cookie(&theme);
        match cx.accept(&["text/html", "application/json"]) {
            Some("application/json") => cx.bytes(200, "application/json", br#"{"page":"home"}"#),
            _ => cx.html(200, "<h1>Home</h1>"),
        }
    }))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: \"rev-7\"\r\n\r\n");
assert_eq!(r.status, 304);
# Ok::<(), web_net::BuildError>(())
```

A closure that reads fields of your own identity type names its parameter,
because Rust checks the closure before the builder fixes the type. Named
functions need nothing extra:

```rust
use web_net::{Context, Identity, Route, get};

struct User { name: String }
impl Identity for User { fn is_guest(&self) -> bool { false } }

fn account(cx: &mut Context<'_, User>) -> web_net::Result {
    let name = cx.identity().name.clone();
    cx.text(200, &name)
}

let by_fn: Route<User, ()> = get("/account", account).allow(());
let by_closure: Route<User, ()> = get("/me", |cx: &mut Context<'_, User>| {
    let name = cx.identity().name.clone();
    cx.text(200, &name)
})
.allow(());
```

## Routes and groups

```rust
use web_net::{App, Group, Route, delete, get, patch, post, put};

let app = App::builder()
    .route(get("/", |cx| cx.html(200, "<h1>Home</h1>")))
    .route(get("/files/*rest", |cx| cx.text(200, &cx.param("rest")?)))
    .route(
        Route::at("/contact")
            .get(|cx| cx.html(200, "<form method=post></form>"))
            .post(|cx| cx.redirect(303, "/contact/thanks"))
            .csrf_exempt("example: the POST changes nothing"),
    )
    .group(
        Group::at("/api")
            .route(post("/items", |cx| cx.text(201, "made")).csrf_exempt("example"))
            .route(put("/items/:id", |cx| cx.text(200, "put")).csrf_exempt("example"))
            .route(patch("/items/:id", |cx| cx.text(200, "patched")).csrf_exempt("example"))
            .route(delete("/items/:id", |cx| cx.text(204, "")).csrf_exempt("example")),
    )
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /files/a/b.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.text(), "a/b.txt");
# Ok::<(), web_net::BuildError>(())
```

- **Patterns**: literal segments, parameters (`:id`, one segment), and one
  wildcard at the end (`*rest`, the rest of the path). Literals are written
  decoded (`/café`). At most `MAX_PARAMS` (8) parameters.
- **Methods**: `HEAD` follows `GET`; `OPTIONS` is answered for every route;
  another method is a 405 with `Allow`. `Route::on(Method, handler)` takes
  any routable method.
- **One way per case**: `get(path, f)` (and `post`, `put`, `patch`,
  `delete`) for one method, `Route::at(path).get(f).post(g)` for several.

`Route` methods (all return `Self`):

| Method | Effect |
|---|---|
| `at(pattern)` | a route with no handler yet |
| `get(f)`, `post(f)`, `put(f)`, `patch(f)`, `delete(f)`, `on(method, f)` | a handler for that method |
| `public()` | anyone may use it (needed only with a gate that has rules) |
| `allow(rule)` | those the gate's rule allows |
| `name(&'static str)` | a name for logs, events, and hooks |
| `template(&'static str)` | the template `cx.render` uses, checked at build |
| `csrf_exempt(reason)` | no CSRF check on its unsafe methods, with the reason |
| `form_limits(form_net::Limits)` | the budgets for its forms |
| `cors(Cors)` | its CORS policy |
| `cache(CachePolicy)` | its `Cache-Control` |
| `work(WorkClass)` | serve-net's work class, for admission (default `Quick`) |

`Group` methods: `at(prefix)`, `route(Route)`, `group(Group)`, `public()`,
`allow(rule)`, `cors(Cors)`, `cache(CachePolicy)`. A group's rule holds for
every route in it: a route's own rule adds to it (both are checked, the
group's first), and a route declared public inside a group with a rule stops
the build. A route that declares its own CORS or cache keeps it; one that
declares none takes the group's.

`Handler<I, E>` is the trait every handler implements; any
`Fn(&mut Context<'_, I, E>) -> Result + Send + Sync + 'static` is one.

## The site: hosts, folder, URLs

`Builder` methods (each returns `Self`, except `render` and `build`):

| Method | Effect |
|---|---|
| `host(&str)` | a host the site answers; the first is canonical; none declared means the development hosts only |
| `any_host()` | every host is the site (behind a front that checked it); not with `host` |
| `alias(&str)` | a host redirected to the canonical one |
| `development()` | with declared hosts, `localhost`, `127.0.0.1`, `[::1]`, `*.localhost` are the site too; HTTPS not required for them |
| `base(&str)` | the folder the site is installed under (`/blog`) |
| `trailing_slash(TrailingSlash)` | `Strip` (default), `Add`, `Ignore` |
| `lowercase_paths()` | upper-case paths are redirected to lower case |
| `https_only()` | plain HTTP is redirected to HTTPS on the canonical host |
| `route(Route)`, `group(Group)` | routes |
| `render(engine)` | the template engine; before routes and hooks |
| `sign_in(path)` | where a sign-in denial on `GET` and `HEAD` sends the visitor (303, with `next`) |
| `www_authenticate(&str)` | the `WWW-Authenticate` value with a 401 (default `Session`) |
| `csrf(csrf_sec::Csrf)` | CSRF protection |
| `redirect_hosts(&[&str])` | hosts `Context::redirect_external` may send to |
| `assets(Assets)`, `health(path)`, `ready(path, check)` | see [Static files](#static-files-and-health) |
| `security_headers(SecurityHeaders)`, `compress(Compression)` | see [Headers](#headers-caching-compression-cors) |
| `hook(Hook, Routes, f)` | see [Hooks](#hooks) |
| `events(impl Events)`, `checkpoint(impl Checkpoint)` | see [Events](#events-and-checkpoints) |
| `page_limit(bytes)` | budget for one rendered page (default `DEFAULT_PAGE_LIMIT`, 8 MiB) |
| `wipe_buffers()` | zero the reused reply buffers after every request |
| `build()` | `Result<App, BuildError>` with every problem listed |

```rust
use web_net::{App, TrailingSlash, get};

let app = App::builder()
    .host("example.com")
    .alias("www.example.com")
    .base("/blog")
    .trailing_slash(TrailingSlash::Strip)
    .route(get("/posts/:slug", |cx| {
        let home = cx.url("/")?;
        cx.html(200, &format!("<a href=\"{home}\">home</a>"))
    }))
    .build()?;

use serve_net::testing::respond;
let r = respond(&app, b"GET /blog/posts/a/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
assert_eq!((r.status, r.header("location")), (301, Some(&b"/blog/posts/a"[..])));
let r = respond(&app, b"GET /blog/posts/a HTTP/1.1\r\nHost: www.example.com\r\n\r\n");
assert_eq!(r.header("location"), Some(&b"http://example.com/blog/posts/a"[..]));
let r = respond(&app, b"GET /blog/posts/a HTTP/1.1\r\nHost: evil.example\r\n\r\n");
assert_eq!(r.status, 421);
# Ok::<(), web_net::BuildError>(())
```

Every path is decoded once and redirected to its one canonical spelling, so
two spellings never reach two routes. An encoded slash, an encoded
backslash, a control character (C0, DEL, or C1), or bytes that are not UTF-8 are refused with
400; `UrlError` names each (`code()` gives `url.encoded_slash` and so on).

## Gates: who is asking, and may they

A gate authenticates every request and authorizes each route's rule. The
default, `Open`, makes everyone a `Guest` and has no rules (`NoRule` has no
values), so every route is public. With your own gate, every route declares
`.public()` or `.allow(rule)`, or the app does not build: a forgotten check
fails at start-up, not in production.

```rust
use web_net::{App, Context, Denial, Gate, Identity, Request, get};

struct User { name: Option<String> }
impl Identity for User {
    fn is_guest(&self) -> bool { self.name.is_none() }
}

enum Rule { SignedIn }

struct Sessions;
impl Gate for Sessions {
    type Identity = User;
    type Rule = Rule;
    fn authenticate(&self, req: &Request<'_>) -> Result<User, Denial> {
        match req.cookie("sid") {
            Ok(Some("ann")) => Ok(User { name: Some("ann".into()) }),
            Ok(_) => Ok(User { name: None }),
            Err(_) => Err(Denial::forbidden("session.ambiguous")),
        }
    }
    fn authorize(&self, who: &User, rule: &Rule, _: &Request<'_>) -> Result<(), Denial> {
        match rule {
            Rule::SignedIn if who.is_guest() => Err(Denial::sign_in("session.none")),
            Rule::SignedIn => Ok(()),
        }
    }
}

let app = App::with_gate(Sessions)
    .sign_in("/login")
    .route(get("/", |cx| cx.text(200, "home")).public())
    .route(get("/login", |cx| cx.text(200, "sign in")).public())
    .route(get("/account", |cx: &mut Context<'_, User>| {
        let name = cx.identity().name.clone().unwrap_or_default();
        cx.text(200, &name)
    })
    .allow(Rule::SignedIn))
    .build()?;

use serve_net::testing::respond;
let r = respond(&app, b"GET /account HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!((r.status, r.header("location")), (303, Some(&b"/login?next=/account"[..])));
let r = respond(&app, b"GET /account HTTP/1.1\r\nHost: localhost\r\nCookie: sid=ann\r\n\r\n");
assert_eq!(r.text(), "ann");
# Ok::<(), web_net::BuildError>(())
```

| Item | What it is |
|---|---|
| `trait Gate { type Identity; type Rule; fn authenticate; fn authorize }` | the one security interface |
| `trait Identity { fn is_guest; fn csrf_binding; fn set_cookie }` | who is asking; `csrf_binding` is the session secret CSRF tokens are bound to; `set_cookie` a field the gate wants on every reply (a dead session cleared) |
| `Open`, `Guest`, `NoRule` | the default gate, its identity, its empty rule type |
| `Denial::sign_in(code)` | 303 to the sign-in page for `GET`/`HEAD`, else 401 |
| `Denial::forbidden(code)` | 403 |
| `Denial::hidden(code)` | 404, hiding that the page exists |
| `Denial::with_status(status, code)` | another 4xx (429, 451); anything else is answered as 403 |
| `Denial::unavailable(code)` | 503: the gate cannot decide now (a store is down) and fails closed; clients retry |
| `Denial::retry_after(seconds)`, `retry_seconds()` | a `Retry-After` field, sent only with 429 and 503 |
| `Denial::with_cookie(value)`, `cookie()` | a `Set-Cookie` the refusal carries |
| `Denial::kind()`, `code()`, `status()` | `DenialKind::{SignIn, Forbidden, Hidden, Status(u16), Unavailable}`, the code, the status |
| `App::with_gate(gate)`, `App::gate()` | an app with your gate; the gate it holds |

## Forms, uploads, CSRF

Every unsafe method (`POST`, `PUT`, `PATCH`, `DELETE`) is checked for CSRF
before its handler runs: csrf-sec's origin policy, then a token bound to the
visitor's session (`Identity::csrf_binding`), from the `X-CSRF-Token` header
or the `csrf_token` field. A route that takes an unsafe method needs
`Builder::csrf` or `Route::csrf_exempt(reason)`, or the app does not build.

```rust
use web_net::form_net::{self, FromForm};
use web_net::{App, Context, Denial, Gate, Identity, Request, csrf_sec::Csrf, get, post};

struct Visitor;
impl Identity for Visitor {
    fn is_guest(&self) -> bool { false }
    fn csrf_binding(&self) -> Option<&[u8]> { Some(b"the session id") }
}
struct Sessions;
impl Gate for Sessions {
    type Identity = Visitor;
    type Rule = ();
    fn authenticate(&self, _: &Request<'_>) -> Result<Visitor, Denial> { Ok(Visitor) }
    fn authorize(&self, _: &Visitor, _: &(), _: &Request<'_>) -> Result<(), Denial> { Ok(()) }
}

form_net::form! {
    pub struct Email { pub email: String }
    ignore = ["csrf_token"];
}

let app = App::with_gate(Sessions)
    .csrf(Csrf::new(*b"a persisted 32-byte secret key!!").unwrap())
    .route(get("/account/email", |cx: &mut Context<'_, Visitor>| {
        let token = cx.csrf_token()?;
        cx.html(200, &format!("<form method=post><input type=hidden name=csrf_token value=\"{token}\">..."))
    }).public())
    .route(post("/account/email", |cx: &mut Context<'_, Visitor>| {
        match cx.form::<Email>() {
            Ok(form) => { let _ = form.email; cx.redirect(303, "/account") }
            Err(e) if e.status_hint() == 422 => cx.html(422, "<p>check the form</p>"),
            Err(e) => Err(e.into()),
        }
    }).public())
    .build()?;

let r = serve_net::testing::respond(&app, b"POST /account/email HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
assert_eq!(r.status, 403); // no token
# Ok::<(), web_net::BuildError>(())
```

| Item | What it does |
|---|---|
| `Context::form::<T>()` | a typed form (urlencoded, or multipart text fields), with the route's `form_limits`; the error keeps form-net's detail for a 422 page |
| `Context::form_inspected::<T, N>(&mut N)` | the same, with an inspector that sees every part first |
| `Context::upload(&Store)` | a multipart upload into a `form_net::Store` (feature `uploads`); `upload_inspected` with an inspector |
| `Context::csrf_token()` | a fresh masked token for the visitor's binding |
| `Builder::csrf(Csrf)`, `Route::csrf_exempt(reason)` | protection, or an exemption with its reason |

Refusal codes: `csrf.no_binding`, `csrf.missing`, `csrf.duplicate`,
`csrf.unreadable_form`, `csrf.no_engine`, and csrf-sec's reasons as
`csrf.<reason>` (`csrf.bad_mac`, `csrf.cross_site`, ...).

## Templates

An engine implements `Render`; web-net depends on none. A typed engine
compiles against the application's own types; a dynamic engine reads any
`View`. Set it with `Builder::render(engine)` before routes and hooks (their
handlers are typed by it).

```rust
use web_net::{App, Context, Guest, Output, Render, RenderError, TemplateId, get};

struct Page<'a> { title: &'a str }
struct Pages;
impl Render for Pages {
    type View<'a> = Page<'a>;
    fn template(&self, name: &str) -> Option<TemplateId> {
        (name == "page").then_some(TemplateId(0))
    }
    fn render(&self, _: TemplateId, page: &Page<'_>, out: &mut Output<'_>) -> Result<(), RenderError> {
        out.write_str("<h1>")?;
        out.write_str(page.title)?; // a real engine escapes
        out.write_str("</h1>")
    }
}

let app = App::builder()
    .render(Pages)
    .route(get("/", |cx: &mut Context<'_, Guest, Pages>| cx.render(&Page { title: "Home" })).template("page"))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.text(), "<h1>Home</h1>");
# Ok::<(), web_net::BuildError>(())
```

A dynamic engine sets `type View<'a> = dyn View + 'a` and reads values by
key. `Fields` is a ready-made view:

```rust
use web_net::{App, Fields, Key, Output, Render, RenderError, TemplateId, Value, View, get};

struct Echo;
impl Render for Echo {
    type View<'a> = dyn View + 'a;
    fn template(&self, _: &str) -> Option<TemplateId> { Some(TemplateId(0)) }
    fn render(&self, _: TemplateId, view: &(dyn View + '_), out: &mut Output<'_>) -> Result<(), RenderError> {
        let key: Key = view.shape().key("title").ok_or(RenderError::new("echo.no_title"))?;
        match view.get(key) {
            Value::Text(t) => out.write_str(t),
            _ => Err(RenderError::new("echo.not_text").with_detail("title")),
        }
    }
}

let app = App::builder()
    .render(Echo)
    .route(get("/", |cx| cx.render_view(&Fields(&[("title", Value::Text("Home"))]))).template("t"))
    .route(get("/named", |cx| cx.render_view_named("t", &Fields(&[("title", Value::Text("Named"))]))))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /named HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.text(), "Named");
# Ok::<(), web_net::BuildError>(())
```

| Item | What it is |
|---|---|
| `trait Render { type View<'a>: ?Sized; fn template; fn render; fn error_page }` | an engine; `error_page` returns `Ok(false)` to keep the built-in page |
| `NoRender` | the default: no templates |
| `ErrorPage { status, title, message, reference, base }`, `ErrorPage::new(..)`, `.with_base(base)` | what an error page shows; `base` is the site's base path (`""` or `/blog`) |
| `ErrorPage::url(path)` | a site path with the base in front, for the page's links and stylesheets |
| `Output` | the page being written: `new(&mut Vec<u8>, limit)`, `write`, `write_str`, `buffer`, `len`, `is_empty`, `remaining` |
| `RenderError` | `new(code)`, `with_detail(..)`, `code()`, `detail()`; answered as 500 |
| `TemplateId(u32)` | an engine's template, resolved at build |
| `trait View { fn shape; fn get; fn call }`, `trait Shape { fn id; fn key }`, `Key(u32)`, `ShapeId(u64)` (`ShapeId::ANONYMOUS`) | a dynamic view and the keys its engine reads |
| `trait List { fn len; fn is_empty; fn get }` | a list value |
| `enum Value { Absent, Bool, Int, Float, Text, Html, Display, View, List }` | one value; `is_absent()`, `as_text()` |
| `SafeHtml::trusted(&str)`, `as_str()` | HTML the engine writes without escaping |
| `escape_html(&str)` | text made safe for HTML, for a handler that writes HTML itself (`cx.html(200, &format!("<p>{}</p>", escape_html(&name)))`) |
| `Fields(&[(&str, Value)])` | a ready-made view |
| `Context::render(&view)`, `Context::render_named(name, &view)` | the route's template, or one by name |
| `Context::render_view(&dyn View)`, `Context::render_view_named(name, &dyn View)` | the same for a dynamic engine (Rust cannot coerce to `dyn View` during inference) |
| `Builder::page_limit(bytes)` | the most one page may write (`DEFAULT_PAGE_LIMIT`, 8 MiB) |

## Static files and health

```rust
use web_net::{App, Assets};

let dir = std::env::temp_dir();
let app = App::builder()
    .assets(Assets::new("/static", &dir).cache_control("public, max-age=31536000, immutable"))
    .health("/healthz")
    .ready("/readyz", || true)
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!((r.status, r.text()), (200, "ok"));
# Ok::<(), web_net::BuildError>(())
```

| Item | What it does |
|---|---|
| `Assets::new(mount, dir)` | a folder served under `mount`, before the gate |
| `.cache_control(value)` | its `Cache-Control` (default `no-cache`) |
| `.index(name)` | the file a folder answers with (default none: folders are 404) |
| `.precompressed(bool)` | serve `file.br` and `file.gz` when accepted (default on) |
| `.hidden_files(bool)` | serve dot files (default off: `.env` is 404) |
| `mime_for(&Path)` | the media type web-net sends for a file name |
| `INLINE_LIMIT` | files up to 1 MiB are read whole; larger go out in parts |
| `Builder::health(path)`, `Builder::ready(path, check)` | `200 ok`; `200 ready` or `503 not ready` |

Files get `ETag`, `Last-Modified`, 304, ranges, and no way out of the folder
(dot segments, encoded slashes, drive letters, device names, and Windows
short names are refused).

- Each mount caches what a path resolved to for two seconds; a hit costs
  one metadata call that does not follow links. Files up to 64 KiB keep
  their bytes in the cache while their length and modification time hold.
- The entity tag is the length and modification time (and the coding), so
  a rewrite of the same size within the file system's time granularity (two
  seconds on FAT, coarse on some network shares) keeps the tag. Files whose
  names change with their content avoid that.
- A file over 1 MiB goes out in 256 KiB parts, chunked: serve-net has no
  stream with a declared length yet, so it carries no `Content-Length`
  (HEAD included). Each part checks the file is the one the first part
  found; a change ends the connection, never with other bytes. At most
  16,384 such replies run at once per application; past that a new one is
  503 with `Retry-After`.

## Headers, caching, compression, CORS

```rust
use web_net::{App, CachePolicy, Compression, Cors, SecurityHeaders, get};

let app = App::builder()
    .security_headers(SecurityHeaders::default().hsts(31_536_000, true))
    .compress(Compression::default().min_bytes(512))
    .route(get("/", |cx| cx.html(200, "<h1>Home</h1>")).cache(CachePolicy::Guests { max_age: 60 }))
    .route(get("/api/items", |cx| cx.bytes(200, "application/json", b"[]"))
        .cors(Cors::new().origin("https://app.example.com").max_age(600)))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.header("cache-control"), Some(&b"public, max-age=60"[..]));
assert!(r.header("content-security-policy").is_some());
# Ok::<(), web_net::BuildError>(())
```

| Item | What it does |
|---|---|
| `SecurityHeaders::default()` | strict defaults: `DEFAULT_CSP`, `X-Frame-Options: DENY`, no-referrer policy, nosniff, opener policy; HSTS on HTTPS |
| `.content_security_policy(v)`, `.no_content_security_policy()` | the CSP |
| `.frame_options(v)`, `.referrer_policy(v)`, `.permissions_policy(v)`, `.opener_policy(v)` | one field each |
| `.hsts(max_age, include_subdomains)`, `.no_hsts()` | HSTS (sent on HTTPS only) |
| `SecurityHeaders::none()` | no security headers (a proxy in front sets them) |
| `CachePolicy::{Unset, NoStore, Private { max_age }, Public { max_age }, Guests { max_age }}` | `Cache-Control` per route or group; a reply that sets a cookie is always `private, no-store` |
| `Compression::default()`, `.min_bytes(n)`, `.level(n)` | gzip for compressible replies (default 1024 bytes, level 6) ; adds `accept-encoding` to `Vary`. A page that carries a secret beside reflected input leaves it off (BREACH) |
| `Cors::new()`, `.origin(o)`, `.any_origin()`, `.headers(&[..])`, `.expose(&[..])`, `.credentials()`, `.max_age(s)` | CORS per route or group; preflights are answered before the gate |
| `Builder::redirect_hosts(&[..])`, `Context::redirect_external(status, url)` | the only way to redirect to another site |
| `Builder::wipe_buffers()` | zero the reused reply buffers after every request |

## Hooks

A hook runs for the routes it selects, at one point of the pipeline. An
error from a hook ends the request with that error.

```rust
use web_net::{App, Hook, Routes, get};

let app = App::builder()
    .hook(Hook::Finish, Routes::prefix("/docs"), |cx| {
        cx.set_header("x-section", "docs");
        Ok(())
    })
    .hook(Hook::Routed, Routes::named(&["home"]), |_cx| Ok(()))
    .hook(Hook::BeforeRender, Routes::all(), |_cx| Ok(()))
    .route(get("/", |cx| cx.text(200, "home")).name("home"))
    .route(get("/docs/intro", |cx| cx.text(200, "intro")))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /docs/intro HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.header("x-section"), Some(&b"docs"[..]));
# Ok::<(), web_net::BuildError>(())
```

| Item | When |
|---|---|
| `Hook::Routed` | after the access check, before the handler |
| `Hook::Finish` | after the handler succeeded |
| `Hook::BeforeRender` | inside `Context::render`, before the engine |
| `Routes::all()`, `Routes::prefix(p)`, `Routes::named(&[..])` | which routes (a prefix matches whole segments) |

## Events and checkpoints

```rust
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use serve_net::{Envelope, Verdict};
use web_net::{App, Checkpoint, Event, EventKind, Events, Stage, get};

#[derive(Default)]
struct NotFound(AtomicU32);
impl Events for NotFound {
    fn event(&self, e: &Event<'_>) {
        if e.kind == EventKind::Refused && e.status == 404 {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Denies everything once locked, at every stage web-net checks.
#[derive(Default)]
struct Lockdown(std::sync::atomic::AtomicBool);
impl Checkpoint for Lockdown {
    fn check(&self, _: &Envelope, _at: Stage) -> Verdict {
        if self.0.load(Ordering::Relaxed) { Verdict::Deny { status: 503 } } else { Verdict::Pass }
    }
}

let seen = Arc::new(NotFound::default());
let app = App::builder()
    .events(Arc::clone(&seen))
    .checkpoint(Lockdown::default())
    .route(get("/", |cx| cx.text(200, "hi")))
    .build()?;
serve_net::testing::respond(&app, b"GET /nope HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(seen.0.load(Ordering::Relaxed), 1);
# Ok::<(), web_net::BuildError>(())
```

| Item | What it is |
|---|---|
| `trait Events { fn event(&self, &Event) }` | where refusals, denials, failures, and panics go; keep it to a counter or a queue push; `Arc<T>` forwards |
| `NoEvents` | the default: reports nothing |
| `Event { kind, id, route, status, code, source }` | one event |
| `EventKind::{Refused, Denied, Failed, Panicked, Revoked}` | what happened |
| `trait Checkpoint { fn check(&self, &Envelope, Stage) -> Verdict }` | in-flight revocation; `Arc<T>` forwards |
| `Stage::{Authorized, BeforeRender}` | where it runs |

## Behind a front, and several sites

A gateway that authenticated a request already calls `App::respond` with
the identity: web-net does not call the gate's `authenticate` (nor write
the gate's cookie), and authorization still runs per route. The report says
which route ran and whether a cache may keep the reply for guests. The
gateway forwards serve-net's `done` to the app too
(`HttpService::done(&app, env, finished)`): a large file sent in parts keeps
a record until its last part or `done`, and without `done` the records of
dropped downloads pile up until new large files are refused with 503.

```rust
use serve_net::{Envelope, HttpReply, HttpRequest, HttpService, Outcome};
use web_net::{App, Cacheable, CachePolicy, Guest, get};

struct Front(App);
impl HttpService for Front {
    fn call(&self, req: &HttpRequest<'_>, env: &Envelope, reply: &mut HttpReply) -> Outcome {
        let served = self.0.respond(req, env, Some(&Guest), reply);
        assert_eq!(served.cache, Cacheable::Guests { max_age: 30 });
        assert!(served.route.is_some());
        served.outcome
    }
}

let app = App::builder()
    .route(get("/", |cx| cx.text(200, "hi")).cache(CachePolicy::Guests { max_age: 30 }))
    .build()?;
let r = serve_net::testing::respond(&Front(app), b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.text(), "hi");
# Ok::<(), web_net::BuildError>(())
```

| Item | What it is |
|---|---|
| `App::listen(addr)` | serve on `addr` with serve-net's defaults; `Result<serve_net::Running, serve_net::ServeError>` |
| `App::respond(req, env, who, reply)` | one request; `who: Option<&Identity>`; returns `Served` |
| `Served { outcome, route, cache }`, `Cacheable::{No, Guests { max_age }}` | what ran |
| `App::classify(&HttpHead)` | `Classified { route: Option<RouteId>, work }` before admission, without answering or calling the gate |
| `RouteId(u32)` | a route, stable for the app's lifetime |
| `impl HttpService for App` | `call` is `respond(.., None, ..)`; `done` frees what the request held |
| `Sites::new().site(app).site(app2)` | several apps in one server, picked by host and base path |
| `Sites::listen(addr)`, `Sites::respond(..)`, `Sites::pick(&HttpRequest)` | as on `App`; which app a request goes to |

```rust
use web_net::{App, Sites, get};

let blog = App::builder().host("example.com").base("/blog").route(get("/", |cx| cx.text(200, "blog"))).build()?;
let main = App::builder().host("example.com").route(get("/", |cx| cx.text(200, "home"))).build()?;
let sites = Sites::new().site(main).site(blog);
let r = serve_net::testing::respond(&sites, b"GET /blog/ HTTP/1.1\r\nHost: example.com\r\n\r\n");
assert_eq!(r.text(), "blog");
# Ok::<(), web_net::BuildError>(())
```

`Request` is what gates and handlers read: `method()`, `path()` (canonical,
inside the site), `query()`, `host()`, `header(name)`, `header_str(name)`,
`cookie(name) -> Result<Option<&str>, Ambiguous>` (a name sent twice is
`Ambiguous`, never resolved by picking one), `client()`, `scheme()`,
`route()` (the matched pattern), `id()`, `envelope()`, `raw()`. `RequestId`
displays as 16 hexadecimal digits, a keyed hash that shows no counter;
`connection()` and `seq()` give the raw values for logs.

## Errors

```rust
use web_net::{App, Error, get};

let app = App::builder()
    .route(get("/report", |_cx| {
        let parsed: Result<u32, _> = "x".parse::<u32>();
        let _n = parsed.map_err(|e| Error::internal("report.parse").with_source(e))?;
        Ok(())
    }))
    .build()?;
let r = serve_net::testing::respond(&app, b"GET /report HTTP/1.1\r\nHost: localhost\r\n\r\n");
assert_eq!(r.status, 500);
assert!(r.text().contains("Reference:"));

let problems = App::builder().base("blog").https_only().build().unwrap_err();
assert_eq!(problems.problems().len(), 2);
# Ok::<(), web_net::BuildError>(())
```

| Item | What it is |
|---|---|
| `Error::new(status, code)` | 400 to 599 (anything else is 500); `code` is stable, for logs |
| `bad_request`, `forbidden`, `not_found`, `conflict`, `unprocessable`, `internal`, `unavailable` | the common statuses |
| `.with_source(err)`, `.status()`, `.code()`, `.source_ref()` | the cause (logs only, never shown), and the parts |
| `Result<T = (), E = Error>` | what handlers return |
| `From<Denial>`, `From<form_net::FormError>`, `From<RenderError>` for `Error` | `?` works on each |
| `BuildError`, `problems() -> &[Problem]`, `Problem { subject, message }` | every mistake `build` found |
| `UrlError::{NotAbsolute, BadEscape, EncodedSlash, Backslash, Control, NotUtf8, TooManySegments}`, `code()` | why a path was refused |

Codes web-net reports: `url.*` (as `UrlError::code`), `host.unknown`,
`site.outside_base`, `route.none`, `route.param`, `route.no_param`,
`assets.none`, `assets.unreadable`, `assets.busy` (503), `cors.denied`,
`method.not_allowed`, `method.unknown`, `query.duplicate`, `query.invalid`,
`url.not_local`, `redirect.not_local`, `redirect.not_allowed`,
`redirect.status`, `render.no_engine`, `render.no_template`,
`render.too_large`, `render.error_page_panic`, `checkpoint.denied`,
`checkpoint.killed`, `reply.invalid_field`, `handler.panic`,
`pipeline.panic`, `precondition.failed`, the `csrf.*` codes, plus the
gates' and handlers' own. A panic anywhere in the application's code on the
request path is answered with the built-in 500 page and reported as
`EventKind::Panicked` (this needs `panic = "unwind"`, the default).

## Constants and re-exports

```rust
assert_eq!(web_net::MAX_PARAMS, 8);
assert_eq!(web_net::DEFAULT_PAGE_LIMIT, 8 << 20);
assert_eq!(web_net::INLINE_LIMIT, 1 << 20);
assert!(web_net::DEFAULT_CSP.starts_with("default-src 'self'"));
assert_eq!(web_net::VERSION.split('.').count(), 3);
```

- `VERSION`: the crate version.
- `MAX_PARAMS`: parameters per route pattern.
- `DEFAULT_PAGE_LIMIT`: the default page budget.
- `INLINE_LIMIT`: files up to this size are read whole.
- `DEFAULT_CSP`: the default content security policy.
- `cookie_net`, `csrf_sec`, `form_net`: the crates web-net uses, at the
  versions it uses, for `Context::set_cookie`, `Builder::csrf`, and `Context::form`.

## Examples in the repository

| Example | Shows |
|---|---|
| `hello` | a small site under a folder: pages, a parameter, a form, `listen` |
| `site` | sessions, sign-in with CSRF, an upload, static files, and pages rendered by Luminess (feature `uploads`) |

Run one with `cargo run --example hello`, or
`cargo run --example site --features uploads`.
