//! Rendering: a template engine behind a trait, reading typed values
//! through a view.
//!
//! No JSON sits between the data and the engine. An engine resolves the
//! names a template uses to [`Key`]s once, when it compiles the template,
//! and reads values by key while it renders: a match or an index per value,
//! no allocation, no parsing. Escaping for each output context (HTML text,
//! attribute, URL, script) is the engine's job; web-net never escapes for it.

use std::borrow::Cow;
use std::fmt;

/// Text made safe to place in HTML, in element content or in a quoted
/// attribute: `&`, `<`, `>`, `"`, and `'` become entities. Borrowed when
/// there is nothing to escape. For a handler that writes HTML itself
/// (`cx.html(200, &format!(..))`); a template engine escapes on its own.
///
/// ```
/// use web_net::{App, escape_html, get};
///
/// let app = App::builder()
///     .route(get("/hi", |cx| {
///         let name = cx.query("name")?.unwrap_or_default();
///         cx.html(200, &format!("<p>Hello, {}</p>", escape_html(&name)))
///     }))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET /hi?name=%3Cscript%3E HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.text(), "<p>Hello, &lt;script&gt;</p>");
/// assert!(matches!(escape_html("plain"), std::borrow::Cow::Borrowed(_)));
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[must_use]
pub fn escape_html(text: &str) -> Cow<'_, str> {
    let Some(first) = text.find(['&', '<', '>', '"', '\'']) else {
        return Cow::Borrowed(text);
    };
    let mut out = String::with_capacity(text.len() + 16);
    out.push_str(&text[..first]);
    for c in text[first..].chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// A template the engine resolved at build time. Its meaning belongs to the
/// engine.
///
/// ```
/// use web_net::TemplateId;
///
/// // An engine gives each template name it knows an id of its own.
/// fn template(name: &str) -> Option<TemplateId> {
///     let names = ["home", "post"];
///     names.iter().position(|n| *n == name).map(|i| TemplateId(i as u32))
/// }
/// assert_eq!(template("post"), Some(TemplateId(1)));
/// assert_eq!(template("missing"), None);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TemplateId(pub u32);

/// A template engine.
///
/// The view type is the engine's: an engine that reads any view through
/// web-net's [`View`] trait (an adapter for a dynamic engine) uses
/// `type View = dyn View`; an engine that compiles templates against the
/// application's own types uses that type, and reads it directly.
///
/// ```
/// use web_net::{Output, Render, RenderError, TemplateId, Value, View};
///
/// /// Writes the view's `title` field and nothing else.
/// struct TitleOnly;
///
/// impl Render for TitleOnly {
///     type View<'a> = dyn View + 'a;
///     fn template(&self, name: &str) -> Option<TemplateId> {
///         (name == "title").then_some(TemplateId(0))
///     }
///     fn render(&self, _t: TemplateId, view: &dyn View, out: &mut Output<'_>) -> Result<(), RenderError> {
///         let key = view.shape().key("title").ok_or(RenderError::new("demo.no_title"))?;
///         match view.get(key) {
///             Value::Text(t) => out.write(t.as_bytes()), // a real engine escapes here
///             _ => Err(RenderError::new("demo.not_text")),
///         }
///     }
/// }
/// ```
pub trait Render: Send + Sync + 'static {
    /// What a handler hands the engine, for any lifetime of the data it
    /// borrows: `dyn View + 'a` for a dynamic engine, the application's own
    /// type (`Page`, or `Page<'a>`) for a typed one.
    type View<'a>: ?Sized;

    /// Resolves a template name. Called at build time for every template a
    /// route names, so an unknown name stops the application from starting.
    fn template(&self, name: &str) -> Option<TemplateId>;

    /// Renders `template` against `view` into `out`.
    ///
    /// # Errors
    ///
    /// A [`RenderError`]; the request is answered with a 500 error page and
    /// the detail goes to the events, never to the visitor.
    fn render(
        &self,
        template: TemplateId,
        view: &Self::View<'_>,
        out: &mut Output<'_>,
    ) -> Result<(), RenderError>;

    /// Writes the page for a refusal or an error, from the facts web-net
    /// shows a visitor. `Ok(false)` (the default) leaves it to web-net's
    /// built-in page; so does an error, which is not reported further.
    ///
    /// # Errors
    ///
    /// A [`RenderError`]; web-net then sends its built-in page.
    fn error_page(&self, page: &ErrorPage<'_>, out: &mut Output<'_>) -> Result<bool, RenderError> {
        let _ = (page, out);
        Ok(false)
    }
}

/// The engine of an application without one: `Context::render` answers 500
/// `render.no_engine`, and error pages are web-net's own.
///
/// ```
/// use web_net::{App, Fields, get};
///
/// let app = App::builder()
///     .route(get("/", |cx| cx.render_view_named("home", &Fields(&[]))))
///     .build()?;
/// let r = serve_net::testing::respond(&app, b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!(r.status, 500); // render.no_engine
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct NoRender;

impl Render for NoRender {
    type View<'a> = dyn View + 'a;

    fn template(&self, _name: &str) -> Option<TemplateId> {
        None
    }

    fn render(
        &self,
        _template: TemplateId,
        _view: &(dyn View + '_),
        _out: &mut Output<'_>,
    ) -> Result<(), RenderError> {
        Err(RenderError::new("render.no_engine"))
    }
}

/// What an error page shows: the status, its generic title and message, and
/// the request's reference. Never the code or the cause.
///
/// `base` is the site's base path (`""` at the root, `/blog` for a site
/// installed in a folder), so the page's links and stylesheets point inside
/// the site: [`url`](Self::url) builds them as [`Context::url`](crate::Context::url)
/// does for pages.
///
/// ```
/// use web_net::{App, ErrorPage, Output, Render, RenderError, TemplateId, View, get};
///
/// /// No templates; its own error pages.
/// struct Plain;
/// impl Render for Plain {
///     type View<'a> = dyn View + 'a;
///     fn template(&self, _: &str) -> Option<TemplateId> { None }
///     fn render(&self, _: TemplateId, _: &dyn View, _: &mut Output<'_>) -> Result<(), RenderError> { Ok(()) }
///     fn error_page(&self, page: &ErrorPage<'_>, out: &mut Output<'_>) -> Result<bool, RenderError> {
///         out.write_str(&format!("{} {}", page.status, page.title))?;
///         Ok(true)
///     }
/// }
///
/// let app = App::builder().render(Plain).route(get("/", |cx| cx.text(200, "home"))).build()?;
/// let r = serve_net::testing::respond(&app, b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n");
/// assert_eq!((r.status, r.text()), (404, "404 Not Found"));
/// # Ok::<(), web_net::BuildError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ErrorPage<'a> {
    /// The status (`404`).
    pub status: u16,
    /// Its generic title (`Not Found`).
    pub title: &'a str,
    /// Its generic message.
    pub message: &'a str,
    /// The request's reference, as the visitor quotes it.
    pub reference: &'a str,
    /// The site's base path: `""` at the root, `/blog` in a folder; never a
    /// trailing slash.
    pub base: &'a str,
}

impl<'a> ErrorPage<'a> {
    /// An error page's facts at the site's root, for an engine's own tests
    /// (web-net makes the real ones).
    ///
    /// ```
    /// let p = web_net::ErrorPage::new(404, "Not Found", "The page was not found.", "1a-2");
    /// assert_eq!((p.status, p.reference, p.base), (404, "1a-2", ""));
    /// ```
    #[must_use]
    pub const fn new(status: u16, title: &'a str, message: &'a str, reference: &'a str) -> Self {
        Self {
            status,
            title,
            message,
            reference,
            base: "",
        }
    }

    /// The same page for a site installed under `base` (`/blog`).
    ///
    /// ```
    /// let p = web_net::ErrorPage::new(404, "Not Found", "-", "r").with_base("/blog");
    /// assert_eq!(p.url("/static/site.css").unwrap(), "/blog/static/site.css");
    /// ```
    #[must_use]
    pub const fn with_base(mut self, base: &'a str) -> Self {
        self.base = base;
        self
    }

    /// A site path as a URL path, the base path in front: what the page's
    /// links and stylesheets use, so they work for a site in a folder.
    ///
    /// ```
    /// let root = web_net::ErrorPage::new(500, "Server Error", "-", "r");
    /// assert_eq!(root.url("/")?, "/");
    /// let blog = root.with_base("/blog");
    /// assert_eq!(blog.url("/static/site.css")?, "/blog/static/site.css");
    /// assert!(blog.url("//elsewhere.example").is_err());
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// `RenderError` `url.not_local` when `path` is not a path of the site
    /// (as for [`Context::url`](crate::Context::url)).
    pub fn url(&self, path: &str) -> Result<String, RenderError> {
        if !crate::cx::is_local_target(path) {
            return Err(RenderError::new("url.not_local"));
        }
        Ok(crate::cx::site_url(self.base, path))
    }
}

/// A field or method of a view, resolved from a name by its [`Shape`].
///
/// ```
/// use web_net::{Fields, Key, Value, View};
///
/// let view = Fields(&[("title", Value::Text("Hello"))]);
/// let key: Key = view.shape().key("title").unwrap();
/// assert_eq!(view.get(key).as_text(), Some("Hello"));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub u32);

/// Identifies a shape so an engine can cache name resolutions per shape.
/// [`ShapeId::ANONYMOUS`] says "do not cache".
///
/// ```
/// use web_net::{Fields, ShapeId, View};
///
/// assert_eq!(Fields(&[]).shape().id(), ShapeId::ANONYMOUS);
/// let post = ShapeId(1); // one fixed shape: an engine may cache what it resolved
/// assert_ne!(post, ShapeId::ANONYMOUS);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeId(pub u64);

impl ShapeId {
    /// A shape whose keys may differ between instances: resolve names per
    /// render.
    ///
    /// ```
    /// use web_net::{Fields, ShapeId, View};
    ///
    /// assert_eq!(ShapeId::ANONYMOUS, ShapeId(0));
    /// assert_eq!(Fields(&[]).shape().id(), ShapeId::ANONYMOUS);
    /// ```
    pub const ANONYMOUS: Self = Self(0);
}

/// The names a view answers.
///
/// ```
/// use web_net::{Key, Shape, ShapeId};
///
/// struct PostShape;
/// impl Shape for PostShape {
///     fn id(&self) -> ShapeId { ShapeId(1) }
///     fn key(&self, name: &str) -> Option<Key> {
///         match name { "title" => Some(Key(0)), "body" => Some(Key(1)), _ => None }
///     }
/// }
/// assert_eq!(PostShape.key("body"), Some(Key(1)));
/// assert_eq!(PostShape.key("author"), None);
/// ```
pub trait Shape {
    /// The shape's identity. Two views with the same id resolve every name
    /// to the same key.
    fn id(&self) -> ShapeId;

    /// The key for a field or method name.
    fn key(&self, name: &str) -> Option<Key>;
}

/// What a template reads.
///
/// ```
/// use web_net::{Key, Shape, ShapeId, Value, View};
///
/// struct Post { title: String, views: i64 }
/// impl Shape for Post {
///     fn id(&self) -> ShapeId { ShapeId(1) }
///     fn key(&self, name: &str) -> Option<Key> {
///         match name { "title" => Some(Key(0)), "views" => Some(Key(1)), _ => None }
///     }
/// }
/// impl View for Post {
///     fn shape(&self) -> &dyn Shape { self }
///     fn get(&self, key: Key) -> Value<'_> {
///         match key.0 { 0 => Value::Text(&self.title), 1 => Value::Int(self.views), _ => Value::Absent }
///     }
/// }
///
/// let post = Post { title: "Hello".into(), views: 3 };
/// let key = post.shape().key("title").unwrap();
/// assert_eq!(post.get(key).as_text(), Some("Hello"));
/// ```
pub trait View {
    /// The names this view answers.
    fn shape(&self) -> &dyn Shape;

    /// A field by key. The hot path: no allocation.
    fn get(&self, key: Key) -> Value<'_>;

    /// A method with arguments (`variations.options("size")`). The result is
    /// passed to `with`, so it may borrow a value computed for the call.
    /// The default answers [`Value::Absent`].
    fn call(&self, key: Key, args: &[Value<'_>], with: &mut dyn FnMut(Value<'_>)) {
        let _ = (key, args);
        with(Value::Absent);
    }
}

/// A sequence a template can loop over.
///
/// ```
/// use web_net::{List, Value};
///
/// struct Tags<'a>(&'a [&'a str]);
/// impl List for Tags<'_> {
///     fn len(&self) -> usize { self.0.len() }
///     fn get(&self, index: usize) -> Value<'_> {
///         self.0.get(index).map_or(Value::Absent, |t| Value::Text(t))
///     }
/// }
///
/// let tags = Tags(&["rust", "web"]);
/// assert_eq!(tags.get(1).as_text(), Some("web"));
/// assert!(tags.get(2).is_absent());
/// assert!(!tags.is_empty());
/// ```
pub trait List {
    /// The number of items.
    fn len(&self) -> usize;

    /// Whether the list is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// An item, or [`Value::Absent`] past the end.
    fn get(&self, index: usize) -> Value<'_>;
}

/// Markup that is trusted as it is: written without escaping. Making one is
/// a visible, searchable step (`SafeHtml::trusted`), and the place to
/// sanitize is where the markup was produced (when content is saved), not
/// here.
///
/// ```
/// use web_net::{SafeHtml, Value};
///
/// // Markup sanitized when it was saved, written as it is.
/// let body = Value::Html(SafeHtml::trusted("<p>Saved <b>post</b></p>"));
/// assert!(matches!(body, Value::Html(h) if h.as_str().starts_with("<p>")));
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SafeHtml<'a>(&'a str);

impl<'a> SafeHtml<'a> {
    /// Marks `html` as trusted markup.
    ///
    /// ```
    /// use web_net::SafeHtml;
    ///
    /// let html = SafeHtml::trusted("<b>saved</b>");
    /// assert_eq!(html.as_str(), "<b>saved</b>");
    /// ```
    #[must_use]
    pub const fn trusted(html: &'a str) -> Self {
        Self(html)
    }

    /// The markup.
    ///
    /// ```
    /// use web_net::SafeHtml;
    ///
    /// let html = SafeHtml::trusted("<em>hi</em>");
    /// assert_eq!(format!("<p>{}</p>", html.as_str()), "<p><em>hi</em></p>");
    /// ```
    #[must_use]
    pub const fn as_str(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for SafeHtml<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafeHtml({} bytes)", self.0.len())
    }
}

/// One value read from a view.
///
/// ```
/// use web_net::{SafeHtml, Value, escape_html};
///
/// // How an engine writes a value into HTML text.
/// fn write(v: Value<'_>) -> String {
///     match v {
///         Value::Text(t) => escape_html(t).into_owned(),
///         Value::Html(h) => h.as_str().to_owned(),
///         Value::Int(i) => i.to_string(),
///         _ => String::new(),
///     }
/// }
/// assert_eq!(write(Value::Text("a<b")), "a&lt;b");
/// assert_eq!(write(Value::Html(SafeHtml::trusted("<b>b</b>"))), "<b>b</b>");
/// assert_eq!(write(Value::Int(3)), "3");
/// ```
#[non_exhaustive]
#[derive(Clone, Copy)]
pub enum Value<'a> {
    /// Nothing here (a missing field, an empty optional).
    Absent,
    /// A boolean.
    Bool(bool),
    /// An integer.
    Int(i64),
    /// A float.
    Float(f64),
    /// Text, escaped for its context by the engine.
    Text(&'a str),
    /// Trusted markup, written as it is.
    Html(SafeHtml<'a>),
    /// A computed value (money, a date), written as text and escaped.
    Display(&'a dyn fmt::Display),
    /// A nested object.
    View(&'a dyn View),
    /// A sequence.
    List(&'a dyn List),
}

impl Value<'_> {
    /// Whether this is [`Value::Absent`].
    ///
    /// ```
    /// use web_net::Value;
    ///
    /// assert!(Value::Absent.is_absent());
    /// assert!(!Value::Int(0).is_absent());
    /// ```
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// The text, for [`Value::Text`].
    ///
    /// ```
    /// use web_net::Value;
    ///
    /// assert_eq!(Value::Text("hi").as_text(), Some("hi"));
    /// assert_eq!(Value::Int(1).as_text(), None);
    /// ```
    #[must_use]
    pub const fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(t) => Some(t),
            _ => None,
        }
    }
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Bool(b) => write!(f, "Bool({b})"),
            Self::Int(i) => write!(f, "Int({i})"),
            Self::Float(x) => write!(f, "Float({x})"),
            Self::Text(t) => write!(f, "Text({t:?})"),
            Self::Html(h) => write!(f, "{h:?}"),
            Self::Display(_) => f.write_str("Display(..)"),
            Self::View(_) => f.write_str("View(..)"),
            Self::List(l) => write!(f, "List({} items)", l.len()),
        }
    }
}

/// A ready-made view over a slice of named values, for small pages, error
/// pages, and tests. Its shape is anonymous: names are looked up per render.
///
/// ```
/// use web_net::{Fields, Value, View};
///
/// let view = Fields(&[("title", Value::Text("Hello")), ("count", Value::Int(3))]);
/// let key = view.shape().key("count").unwrap();
/// assert!(matches!(view.get(key), Value::Int(3)));
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a>(pub &'a [(&'a str, Value<'a>)]);

impl Shape for Fields<'_> {
    fn id(&self) -> ShapeId {
        ShapeId::ANONYMOUS
    }

    fn key(&self, name: &str) -> Option<Key> {
        self.0
            .iter()
            .position(|(n, _)| *n == name)
            .map(|i| Key(i as u32))
    }
}

impl View for Fields<'_> {
    fn shape(&self) -> &dyn Shape {
        self
    }

    fn get(&self, key: Key) -> Value<'_> {
        self.0
            .get(key.0 as usize)
            .map_or(Value::Absent, |(_, v)| *v)
    }
}

/// Where an engine writes: the reply body, reused between requests, with a
/// size budget.
///
/// ```
/// use web_net::Output;
///
/// let mut buf = Vec::new();
/// let mut out = Output::new(&mut buf, 64);
/// out.write_str("<p>hi</p>")?;
/// assert_eq!(out.remaining(), 55);
/// assert_eq!(buf, b"<p>hi</p>");
/// # Ok::<(), web_net::RenderError>(())
/// ```
pub struct Output<'a> {
    buf: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> Output<'a> {
    /// An output over `buf`, refusing to grow past `limit` bytes.
    ///
    /// ```
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 4);
    /// assert!(out.write(b"1234").is_ok());
    /// assert_eq!(out.write(b"5").unwrap_err().code(), "render.too_large");
    /// ```
    #[must_use]
    pub fn new(buf: &'a mut Vec<u8>, limit: usize) -> Self {
        Self { buf, limit }
    }

    /// Appends bytes.
    ///
    /// ```
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 64);
    /// out.write(b"<p>")?;
    /// assert_eq!(out.len(), 3);
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// `render.too_large` when the page would pass the budget.
    #[inline]
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), RenderError> {
        if self.buf.len() + bytes.len() > self.limit {
            return Err(RenderError::new("render.too_large"));
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Appends a string.
    ///
    /// ```
    /// use web_net::{Output, escape_html};
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 64);
    /// out.write_str(&escape_html("a<b"))?;
    /// assert_eq!(buf, b"a&lt;b");
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// As [`write`](Self::write).
    #[inline]
    pub fn write_str(&mut self, s: &str) -> Result<(), RenderError> {
        self.write(s.as_bytes())
    }

    /// The buffer itself, for an engine that writes into a `Vec<u8>`. The
    /// budget is checked when the engine returns: a page past it is refused
    /// with `render.too_large`.
    ///
    /// ```
    /// use std::io::Write;
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 64);
    /// write!(out.buffer(), "{} items", 3).unwrap();
    /// assert_eq!(out.len(), 7);
    /// ```
    pub fn buffer(&mut self) -> &mut Vec<u8> {
        self.buf
    }

    /// Whether the budget was passed (checked after the engine returns).
    pub(crate) fn over(&self) -> bool {
        self.buf.len() > self.limit
    }

    /// Bytes written so far.
    ///
    /// ```
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 64);
    /// out.write_str("hello")?;
    /// assert_eq!(out.len(), 5);
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was written yet.
    ///
    /// ```
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 64);
    /// assert!(out.is_empty());
    /// out.write_str("x")?;
    /// assert!(!out.is_empty());
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The bytes still allowed.
    ///
    /// ```
    /// use web_net::Output;
    ///
    /// let mut buf = Vec::new();
    /// let mut out = Output::new(&mut buf, 10);
    /// out.write_str("abc")?;
    /// assert_eq!(out.remaining(), 7);
    /// # Ok::<(), web_net::RenderError>(())
    /// ```
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.buf.len())
    }
}

impl fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Output")
            .field("len", &self.buf.len())
            .field("limit", &self.limit)
            .finish()
    }
}

/// A render failure. The code is stable; the detail is for logs only.
///
/// ```
/// use web_net::RenderError;
///
/// let e = RenderError::new("demo.missing_block").with_detail("page.html line 3");
/// assert_eq!(e.code(), "demo.missing_block");
/// assert_eq!(e.to_string(), "render failed (demo.missing_block): page.html line 3");
/// ```
pub struct RenderError {
    code: &'static str,
    detail: Option<Box<str>>,
}

impl RenderError {
    /// A failure with a stable code (`"luminess.missing_block"`).
    ///
    /// ```
    /// use web_net::RenderError;
    ///
    /// let e = RenderError::new("demo.missing_block");
    /// assert_eq!((e.code(), e.detail()), ("demo.missing_block", None));
    /// ```
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }

    /// Adds a detail for the logs (a template name, a line number).
    ///
    /// ```
    /// use web_net::RenderError;
    ///
    /// let e = RenderError::new("demo.missing_block").with_detail("page.html line 3");
    /// assert_eq!(e.detail(), Some("page.html line 3"));
    /// ```
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<Box<str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The code.
    ///
    /// ```
    /// use web_net::RenderError;
    ///
    /// assert_eq!(RenderError::new("render.too_large").code(), "render.too_large");
    /// ```
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The detail, if any.
    ///
    /// ```
    /// use web_net::RenderError;
    ///
    /// assert_eq!(RenderError::new("demo.bad").detail(), None);
    /// assert_eq!(RenderError::new("demo.bad").with_detail("line 3").detail(), Some("line 3"));
    /// ```
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

impl fmt::Debug for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderError")
            .field("code", &self.code)
            .field("detail", &self.detail)
            .finish()
    }
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.detail {
            Some(d) => write!(f, "render failed ({}): {d}", self.code),
            None => write!(f, "render failed ({})", self.code),
        }
    }
}

impl std::error::Error for RenderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_budget() {
        let mut buf = Vec::new();
        let mut out = Output::new(&mut buf, 4);
        out.write(b"abc").unwrap();
        assert_eq!(out.remaining(), 1);
        assert_eq!(out.write(b"de").unwrap_err().code(), "render.too_large");
        out.write(b"d").unwrap();
        assert_eq!(buf, b"abcd");
    }

    #[test]
    fn test_fields_view() {
        let v = Fields(&[("a", Value::Bool(true)), ("b", Value::Text("x"))]);
        assert_eq!(v.shape().key("b"), Some(Key(1)));
        assert_eq!(v.shape().key("c"), None);
        assert!(v.get(Key(9)).is_absent());
        assert_eq!(v.get(Key(1)).as_text(), Some("x"));
        let mut got = false;
        v.call(Key(0), &[], &mut |x| got = x.is_absent());
        assert!(got);
    }
}
