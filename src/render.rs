//! Rendering: a template engine behind a trait, reading typed values
//! through a view.
//!
//! No JSON sits between the data and the engine. An engine resolves the
//! names a template uses to [`Key`]s once, when it compiles the template,
//! and reads values by key while it renders: a match or an index per value,
//! no allocation, no parsing. Escaping for each output context (HTML text,
//! attribute, URL, script) is the engine's job; web-net never escapes for it.

use std::fmt;

/// A template the engine resolved at build time. Its meaning belongs to the
/// engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TemplateId(pub u32);

/// A template engine.
///
/// ```
/// use web_net::{Output, Render, RenderError, TemplateId, Value, View};
///
/// /// Writes the view's `title` field and nothing else.
/// struct TitleOnly;
///
/// impl Render for TitleOnly {
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
        view: &dyn View,
        out: &mut Output<'_>,
    ) -> Result<(), RenderError>;
}

/// A field or method of a view, resolved from a name by its [`Shape`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub u32);

/// Identifies a shape so an engine can cache name resolutions per shape.
/// [`ShapeId::ANONYMOUS`] says "do not cache".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShapeId(pub u64);

impl ShapeId {
    /// A shape whose keys may differ between instances: resolve names per
    /// render.
    pub const ANONYMOUS: Self = Self(0);
}

/// The names a view answers.
pub trait Shape {
    /// The shape's identity. Two views with the same id resolve every name
    /// to the same key.
    fn id(&self) -> ShapeId;

    /// The key for a field or method name.
    fn key(&self, name: &str) -> Option<Key>;
}

/// What a template reads.
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
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SafeHtml<'a>(&'a str);

impl<'a> SafeHtml<'a> {
    /// Marks `html` as trusted markup.
    #[must_use]
    pub const fn trusted(html: &'a str) -> Self {
        Self(html)
    }

    /// The markup.
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
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    /// The text, for [`Value::Text`].
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
pub struct Output<'a> {
    buf: &'a mut Vec<u8>,
    limit: usize,
}

impl<'a> Output<'a> {
    /// An output over `buf`, refusing to grow past `limit` bytes.
    #[must_use]
    pub fn new(buf: &'a mut Vec<u8>, limit: usize) -> Self {
        Self { buf, limit }
    }

    /// Appends bytes.
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
    /// # Errors
    ///
    /// As [`write`](Self::write).
    #[inline]
    pub fn write_str(&mut self, s: &str) -> Result<(), RenderError> {
        self.write(s.as_bytes())
    }

    /// Bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// The bytes still allowed.
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
pub struct RenderError {
    code: &'static str,
    detail: Option<Box<str>>,
}

impl RenderError {
    /// A failure with a stable code (`"luminess.missing_block"`).
    #[must_use]
    pub const fn new(code: &'static str) -> Self {
        Self { code, detail: None }
    }

    /// Adds a detail for the logs (a template name, a line number).
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<Box<str>>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// The code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// The detail, if any.
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
