//! A small site: a home page, a page per user, a form that redirects after
//! POST, and the site installed under `/app`.
//!
//! ```text
//! cargo run --example hello
//! curl -i http://127.0.0.1:8091/app/
//! curl -i http://127.0.0.1:8091/app/users/7
//! curl -i http://127.0.0.1:8091/app/users/7/      # 301 to the canonical path
//! curl -i -X DELETE http://127.0.0.1:8091/app/    # 405 with Allow
//! ```

use web_net::{App, Route, get};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = App::builder()
        .host("127.0.0.1:8091")
        .development()
        .base("/app")
        .route(get("/", |cx| {
            let users = cx.url("/users/7")?;
            cx.html(
                200,
                &format!("<h1>Hello</h1><a href=\"{users}\">user 7</a>"),
            )
        }))
        .route(get("/users/:id", |cx| {
            let id: u64 = cx.param_as("id")?;
            cx.text(200, &format!("user {id}"))
        }))
        .route(
            Route::at("/contact")
                .get(|cx| cx.html(200, "<form method=post><button>Send</button></form>"))
                .post(|cx| cx.redirect(303, "/"))
                // A form that changes state gets Builder::csrf(..) and a gate
                // whose identities carry a CSRF binding instead.
                .csrf_exempt("demo: the POST changes nothing"),
        )
        .build()?;

    println!("listening on http://127.0.0.1:8091/app/");
    app.listen("127.0.0.1:8091")?.wait();
    Ok(())
}
