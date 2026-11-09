//! An engine typed by the application's own view (the shape a compiled
//! engine such as Luminess implements), with a view that borrows.

use serve_net::testing::respond;
use web_net::{App, Cx, ErrorPage, Guest, Open, Output, Render, RenderError, TemplateId, get};

/// The application's page, borrowing what the handler has.
struct Page<'a> {
    title: &'a str,
    items: &'a [String],
}

/// A tiny compiled engine: one template, typed against `Page`.
struct Pages;

impl Render for Pages {
    type View<'a> = Page<'a>;

    fn template(&self, name: &str) -> Option<TemplateId> {
        (name == "list").then_some(TemplateId(7))
    }

    fn render(
        &self,
        t: TemplateId,
        page: &Page<'_>,
        out: &mut Output<'_>,
    ) -> Result<(), RenderError> {
        if t != TemplateId(7) {
            return Err(RenderError::new("pages.unknown"));
        }
        let buf = out.buffer();
        buf.extend_from_slice(b"<h1>");
        buf.extend_from_slice(page.title.replace('<', "&lt;").as_bytes());
        buf.extend_from_slice(b"</h1>");
        for i in page.items {
            buf.extend_from_slice(b"<li>");
            buf.extend_from_slice(i.as_bytes());
        }
        Ok(())
    }

    fn error_page(&self, page: &ErrorPage<'_>, out: &mut Output<'_>) -> Result<bool, RenderError> {
        out.write_str(&format!("[{} {}]", page.status, page.title))?;
        Ok(true)
    }
}

#[test]
fn test_typed_engine_renders_borrowed_views() {
    let app = App::with(Open, Pages)
        .page_limit(64)
        .route(
            get("/", |cx: &mut Cx<'_, Guest, Pages>| {
                let items = vec!["a".to_owned(), "b".to_owned()];
                let title = String::from("Hi <you>");
                cx.render(&Page {
                    title: &title,
                    items: &items,
                })
            })
            .public()
            .template("list"),
        )
        .route(
            get("/big", |cx: &mut Cx<'_, Guest, Pages>| {
                let items = vec!["x".repeat(100)];
                cx.render(&Page {
                    title: "big",
                    items: &items,
                })
            })
            .public()
            .template("list"),
        )
        .build()
        .unwrap();
    let r = respond(&app, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.text(), "<h1>Hi &lt;you></h1><li>a<li>b");
    // The budget holds even for an engine that writes into the buffer.
    let r = respond(&app, b"GET /big HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!(r.status, 500);
    // Error pages are the engine's.
    let r = respond(&app, b"GET /nope HTTP/1.1\r\nHost: a\r\n\r\n");
    assert_eq!((r.status, r.text()), (404, "[404 Not Found]"));
}

#[test]
fn test_engine_after_routes_is_a_build_error() {
    let e = App::builder()
        .route(
            get("/", |cx| {
                cx.text(200, "x");
                Ok(())
            })
            .public(),
        )
        .render(Pages)
        .build()
        .unwrap_err();
    assert!(e.problems().iter().any(|p| p.subject == "render"), "{e}");
}
