//! Route declarations: a path, its methods and handlers, and its access.

use std::sync::Arc;

use serve_net::{Method, WorkClass};

use crate::{Cx, NoRender, Render, Result};

/// A request handler. Any `Fn(&mut Cx<'_, I, E>) -> web_net::Result` is one.
pub trait Handler<I, E: Render = NoRender>: Send + Sync + 'static {
    /// Handles one cleared request.
    ///
    /// # Errors
    ///
    /// An [`Error`](crate::Error), answered with the site's error page for
    /// its status.
    fn call(&self, cx: &mut Cx<'_, I, E>) -> Result;
}

impl<I, E: Render, F> Handler<I, E> for F
where
    F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
{
    #[inline]
    fn call(&self, cx: &mut Cx<'_, I, E>) -> Result {
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

pub(crate) type BoxHandler<I, E> = Arc<dyn Handler<I, E>>;

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
///     .route(get("/", |cx| cx.html(200, "<h1>Home</h1>")))
///     .route(
///         Route::at("/contact")
///             .get(|cx| cx.html(200, "<form method=post></form>"))
///             .post(|cx| cx.redirect(303, "/contact/thanks"))
///             // A real form gets CSRF protection: Builder::csrf and a gate
///             // whose identities carry a binding.
///             .csrf_exempt("example: the POST changes nothing"),
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
///     cx.text(200, &name)
/// })
/// .allow(Rule::SignedIn);
/// # let _ = account;
/// ```
pub struct Route<I, R, E: Render = NoRender> {
    pub(crate) pattern: String,
    pub(crate) handlers: Vec<(Method, BoxHandler<I, E>)>,
    pub(crate) access: Access<R>,
    pub(crate) name: Option<&'static str>,
    pub(crate) work: WorkClass,
    pub(crate) template: Option<&'static str>,
    pub(crate) csrf_exempt: Option<&'static str>,
    pub(crate) form_limits: form_net::Limits,
    pub(crate) cors: Option<Arc<crate::Cors>>,
    pub(crate) cache: crate::CachePolicy,
}

impl<I: 'static, R, E: Render> Route<I, R, E> {
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
            csrf_exempt: None,
            form_limits: form_net::Limits::DEFAULT,
            cors: None,
            cache: crate::CachePolicy::Unset,
        }
    }

    /// Adds a handler for `method`. `HEAD` follows `GET` unless it has its
    /// own; `OPTIONS` is answered for every route unless it has its own.
    #[must_use]
    pub fn on(mut self, method: Method, handler: impl Handler<I, E>) -> Self {
        self.handlers.push((method, Arc::new(handler)));
        self
    }

    /// Adds a `GET` handler.
    #[must_use]
    pub fn get<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Get, f)
    }

    /// Adds a `POST` handler.
    #[must_use]
    pub fn post<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Post, f)
    }

    /// Adds a `PUT` handler.
    #[must_use]
    pub fn put<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Put, f)
    }

    /// Adds a `PATCH` handler.
    #[must_use]
    pub fn patch<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Patch, f)
    }

    /// Adds a `DELETE` handler.
    #[must_use]
    pub fn delete<F>(self, f: F) -> Self
    where
        F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
    {
        self.on(Method::Delete, f)
    }

    /// Anyone may use the route, guests included. With a gate that has
    /// rules, public is a declaration, never a default: a route with neither
    /// `public` nor `allow` stops the build. With [`Open`](crate::Open),
    /// whose rule type has no values, every route is public and needs
    /// neither.
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

    /// Takes the route out of CSRF protection, with the reason (a webhook
    /// signed by its sender, an API authenticated by a bearer token that a
    /// browser never sends on its own). The reason is required and must not
    /// be empty: an exemption is a decision, never a default.
    #[must_use]
    pub fn csrf_exempt(mut self, reason: &'static str) -> Self {
        self.csrf_exempt = Some(reason);
        self
    }

    /// The budgets for reading this route's forms (field count, sizes, files;
    /// default `form_net::Limits::DEFAULT`). Keep them to what the form
    /// needs: they bound what one request can make the server hold.
    #[must_use]
    pub fn form_limits(mut self, limits: form_net::Limits) -> Self {
        self.form_limits = limits;
        self
    }

    /// The route's CORS policy: preflights answered, replies to allowed
    /// origins readable by their scripts.
    #[must_use]
    pub fn cors(mut self, cors: crate::Cors) -> Self {
        self.cors = Some(Arc::new(cors));
        self
    }

    /// How the route's pages may be cached.
    #[must_use]
    pub fn cache(mut self, policy: crate::CachePolicy) -> Self {
        self.cache = policy;
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

impl<I, R, E: Render> std::fmt::Debug for Route<I, R, E> {
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
        pub fn $fn<I: 'static, R, E: Render, F>(pattern: impl Into<String>, f: F) -> Route<I, R, E>
        where
            F: Fn(&mut Cx<'_, I, E>) -> Result + Send + Sync + 'static,
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
///         Group::at("/docs")
///             .route(get("/", |cx| cx.text(200, "index")))
///             .route(get("/:page", |cx| cx.text(200, "page"))),
///     )
///     .build()?;
/// # Ok::<(), web_net::BuildError>(())
/// ```
pub struct Group<I, R, E: Render = NoRender> {
    pub(crate) prefix: String,
    pub(crate) access: Access<R>,
    pub(crate) routes: Vec<Route<I, R, E>>,
    pub(crate) cors: Option<Arc<crate::Cors>>,
    pub(crate) cache: crate::CachePolicy,
}

impl<I: 'static, R, E: Render> Group<I, R, E> {
    /// A group under `prefix` (`/admin`).
    #[must_use]
    pub fn at(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            access: Access::Undeclared,
            routes: Vec::new(),
            cors: None,
            cache: crate::CachePolicy::Unset,
        }
    }

    /// The CORS policy of routes that declare none.
    #[must_use]
    pub fn cors(mut self, cors: crate::Cors) -> Self {
        self.cors = Some(Arc::new(cors));
        self
    }

    /// The cache policy of routes that declare none.
    #[must_use]
    pub fn cache(mut self, policy: crate::CachePolicy) -> Self {
        self.cache = policy;
        self
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
    pub fn route(mut self, route: Route<I, R, E>) -> Self {
        self.routes.push(route);
        self
    }

    /// Adds a nested group; its prefix is joined to this one, and it takes
    /// this group's access when it declares none.
    #[must_use]
    pub fn group(mut self, group: Group<I, R, E>) -> Self {
        let inherited = match &group.access {
            Access::Undeclared => self.access.clone(),
            a => a.clone(),
        };
        let cors = group.cors.or_else(|| self.cors.clone());
        let cache = if group.cache == crate::CachePolicy::Unset {
            self.cache
        } else {
            group.cache
        };
        for mut r in group.routes {
            r.pattern = join(&group.prefix, &r.pattern);
            if matches!(r.access, Access::Undeclared) {
                r.access = inherited.clone();
            }
            if r.cors.is_none() {
                r.cors.clone_from(&cors);
            }
            if r.cache == crate::CachePolicy::Unset {
                r.cache = cache;
            }
            self.routes.push(r);
        }
        self
    }

    pub(crate) fn into_routes(self) -> impl Iterator<Item = Route<I, R, E>> {
        let prefix = self.prefix;
        let access = self.access;
        let cors = self.cors;
        let cache = self.cache;
        self.routes.into_iter().map(move |mut r| {
            r.pattern = join(&prefix, &r.pattern);
            if matches!(r.access, Access::Undeclared) {
                r.access = access.clone();
            }
            if r.cors.is_none() {
                r.cors.clone_from(&cors);
            }
            if r.cache == crate::CachePolicy::Unset {
                r.cache = cache;
            }
            r
        })
    }
}

impl<I, R, E: Render> std::fmt::Debug for Group<I, R, E> {
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
