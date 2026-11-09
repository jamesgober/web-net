//! Route declarations: a path, its methods and handlers, and its access.

use std::sync::Arc;

use serve_net::{Method, WorkClass};

use crate::{Cx, Result};

/// A request handler. Any `Fn(&mut Cx<'_, I>) -> web_net::Result` is one.
pub trait Handler<I>: Send + Sync + 'static {
    /// Handles one cleared request.
    ///
    /// # Errors
    ///
    /// An [`Error`](crate::Error), answered with the site's error page for
    /// its status.
    fn call(&self, cx: &mut Cx<'_, I>) -> Result;
}

impl<I, F> Handler<I> for F
where
    F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
{
    #[inline]
    fn call(&self, cx: &mut Cx<'_, I>) -> Result {
        self(cx)
    }
}

/// Who may use a route.
#[derive(Debug)]
pub(crate) enum Access<R> {
    /// Not declared: the build refuses the route.
    Undeclared,
    /// Anyone, guests included; the gate's `authorize` is not called.
    Public,
    /// Those the rule allows.
    Rule(Arc<R>),
}

impl<R> Clone for Access<R> {
    fn clone(&self) -> Self {
        match self {
            Self::Undeclared => Self::Undeclared,
            Self::Public => Self::Public,
            Self::Rule(r) => Self::Rule(Arc::clone(r)),
        }
    }
}

pub(crate) type BoxHandler<I> = Arc<dyn Handler<I>>;

/// A route: a path pattern, one handler per method, and who may use it.
///
/// Patterns are made of literal segments, parameters (`:id`, one segment)
/// and one wildcard at the end (`*rest`, the rest of the path). Literals are
/// written decoded (`/café`); web-net compares them with the canonical
/// request path.
///
/// ```
/// use web_net::{App, get, Route};
///
/// let app = App::builder()
///     .route(get("/", |cx| { cx.html(200, "<h1>Home</h1>"); Ok(()) }).public())
///     .route(
///         Route::at("/contact")
///             .get(|cx| { cx.html(200, "<form method=post></form>"); Ok(()) })
///             .post(|cx| { cx.see_other("/contact/thanks") })
///             .public(),
///     )
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
///
/// A closure that reads fields of a custom identity types its parameter,
/// because the closure is checked before the builder fixes the type (a
/// named `fn` handler needs nothing extra):
///
/// ```
/// use web_net::{Cx, Route, get};
///
/// struct User { name: String }
/// impl web_net::Identity for User {
///     fn is_guest(&self) -> bool { self.name.is_empty() }
/// }
/// enum Rule { SignedIn }
///
/// let account: Route<User, Rule> = get("/account", |cx: &mut Cx<'_, User>| {
///     let name = cx.identity().name.clone();
///     cx.text(200, &name);
///     Ok(())
/// })
/// .allow(Rule::SignedIn);
/// # let _ = account;
/// ```
pub struct Route<I, R> {
    pub(crate) pattern: String,
    pub(crate) handlers: Vec<(Method, BoxHandler<I>)>,
    pub(crate) access: Access<R>,
    pub(crate) name: Option<&'static str>,
    pub(crate) work: WorkClass,
    pub(crate) template: Option<&'static str>,
}

impl<I: 'static, R> Route<I, R> {
    /// A route at `pattern` with no methods yet.
    #[must_use]
    pub fn at(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            handlers: Vec::new(),
            access: Access::Undeclared,
            name: None,
            work: WorkClass::Quick,
            template: None,
        }
    }

    /// Adds a handler for `method`. `HEAD` follows `GET` unless it has its
    /// own; `OPTIONS` is answered for every route unless it has its own.
    #[must_use]
    pub fn on(mut self, method: Method, handler: impl Handler<I>) -> Self {
        self.handlers.push((method, Arc::new(handler)));
        self
    }

    /// Adds a `GET` handler.
    #[must_use]
    pub fn get<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Get, f)
    }

    /// Adds a `POST` handler.
    #[must_use]
    pub fn post<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Post, f)
    }

    /// Adds a `PUT` handler.
    #[must_use]
    pub fn put<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Put, f)
    }

    /// Adds a `PATCH` handler.
    #[must_use]
    pub fn patch<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Patch, f)
    }

    /// Adds a `DELETE` handler.
    #[must_use]
    pub fn delete<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Delete, f)
    }

    /// Anyone may use the route, guests included. Public is a declaration,
    /// never a default: a route with neither `public` nor `allow` stops the
    /// build.
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access = Access::Public;
        self
    }

    /// Those `rule` allows may use the route; the gate's `authorize` decides
    /// on every request.
    #[must_use]
    pub fn allow(mut self, rule: R) -> Self {
        self.access = Access::Rule(Arc::new(rule));
        self
    }

    /// A name for logs, events, and hooks.
    #[must_use]
    pub fn name(mut self, name: &'static str) -> Self {
        self.name = Some(name);
        self
    }

    /// How the handlers behave: `Quick` (the default), `Io`, or `Cpu`. A
    /// dispatcher in front of web-net reads it through
    /// [`App::classify`](crate::App::classify) to move slow work off the
    /// connection's worker.
    #[must_use]
    pub fn work(mut self, work: WorkClass) -> Self {
        self.work = work;
        self
    }

    /// The template [`Cx::render`](crate::Cx::render) uses. Resolved when the
    /// application is built: an unknown name stops the build.
    #[must_use]
    pub fn template(mut self, name: &'static str) -> Self {
        self.template = Some(name);
        self
    }
}

impl<I, R> std::fmt::Debug for Route<I, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("pattern", &self.pattern)
            .field(
                "methods",
                &self.handlers.iter().map(|(m, _)| *m).collect::<Vec<_>>(),
            )
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

macro_rules! method_fn {
    ($(#[$doc:meta])* $fn:ident, $m:ident) => {
        $(#[$doc])*
        #[must_use]
        pub fn $fn<I: 'static, R, F>(pattern: impl Into<String>, f: F) -> Route<I, R>
        where
            F: Fn(&mut Cx<'_, I>) -> Result + Send + Sync + 'static,
        {
            Route::at(pattern).on(Method::$m, f)
        }
    };
}

method_fn!(
    /// A route with a `GET` handler (and so `HEAD`).
    get, Get
);
method_fn!(
    /// A route with a `POST` handler.
    post, Post
);
method_fn!(
    /// A route with a `PUT` handler.
    put, Put
);
method_fn!(
    /// A route with a `PATCH` handler.
    patch, Patch
);
method_fn!(
    /// A route with a `DELETE` handler.
    delete, Delete
);

/// Routes sharing a path prefix and a default access.
///
/// A route that declares its own access keeps it; one that declares none
/// takes the group's.
///
/// ```
/// use web_net::{App, Group, get};
///
/// let app = App::builder()
///     .group(
///         Group::new("/docs")
///             .public()
///             .route(get("/", |cx| { cx.text(200, "index"); Ok(()) }))
///             .route(get("/:page", |cx| { cx.text(200, "page"); Ok(()) })),
///     )
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Group<I, R> {
    pub(crate) prefix: String,
    pub(crate) access: Access<R>,
    pub(crate) routes: Vec<Route<I, R>>,
}

impl<I: 'static, R> Group<I, R> {
    /// A group under `prefix` (`/admin`).
    #[must_use]
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            access: Access::Undeclared,
            routes: Vec::new(),
        }
    }

    /// Routes without their own access are public.
    #[must_use]
    pub fn public(mut self) -> Self {
        self.access = Access::Public;
        self
    }

    /// Routes without their own access need `rule`.
    #[must_use]
    pub fn allow(mut self, rule: R) -> Self {
        self.access = Access::Rule(Arc::new(rule));
        self
    }

    /// Adds a route; its pattern is joined to the prefix.
    #[must_use]
    pub fn route(mut self, route: Route<I, R>) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a nested group; its prefix is joined to this one, and it takes
    /// this group's access when it declares none.
    #[must_use]
    pub fn group(mut self, group: Group<I, R>) -> Self {
        let inherited = match &group.access {
            Access::Undeclared => self.access.clone(),
            a => a.clone(),
        };
        for mut r in group.routes {
            r.pattern = join(&group.prefix, &r.pattern);
            if matches!(r.access, Access::Undeclared) {
                r.access = inherited.clone();
            }
            self.routes.push(r);
        }
        self
    }

    pub(crate) fn into_routes(self) -> impl Iterator<Item = Route<I, R>> {
        let prefix = self.prefix;
        let access = self.access;
        self.routes.into_iter().map(move |mut r| {
            r.pattern = join(&prefix, &r.pattern);
            if matches!(r.access, Access::Undeclared) {
                r.access = access.clone();
            }
            r
        })
    }
}

impl<I, R> std::fmt::Debug for Group<I, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("prefix", &self.prefix)
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

/// `/admin` + `/` = `/admin`; `/admin` + `/users` = `/admin/users`.
pub(crate) fn join(prefix: &str, pattern: &str) -> String {
    let p = prefix.trim_end_matches('/');
    if pattern == "/" || pattern.is_empty() {
        if p.is_empty() { "/".into() } else { p.into() }
    } else if pattern.starts_with('/') {
        format!("{p}{pattern}")
    } else {
        format!("{p}/{pattern}")
    }
}

#[cfg(test)]
mod tests {
    use super::join;

    #[test]
    fn test_join() {
        assert_eq!(join("/admin", "/"), "/admin");
        assert_eq!(join("/admin/", "/users"), "/admin/users");
        assert_eq!(join("/", "/x"), "/x");
        assert_eq!(join("", "/"), "/");
        assert_eq!(join("/a", "b"), "/a/b");
    }
}
