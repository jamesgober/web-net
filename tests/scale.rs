//! The router at 10,000 routes: every route reachable, precedence kept,
//! build time bounded.

use std::time::{Duration, Instant};

use serve_net::testing::respond;
use web_net::{App, get};

#[test]
fn test_ten_thousand_routes() {
    let start = Instant::now();
    let mut b = App::builder();
    for i in 0..10_000u32 {
        let pattern = match i % 4 {
            0 => format!("/s{i}"),
            1 => format!("/s{i}/items/:id"),
            2 => format!("/s{i}/files/*rest"),
            _ => format!("/s{i}/a/b/c/:x/d"),
        };
        b = b.route(
            get(pattern, move |cx| {
                let p = cx
                    .param("id")
                    .or_else(|| cx.param("rest"))
                    .or_else(|| cx.param("x"));
                cx.text(200, &format!("{i}:{}", p.unwrap_or_default()));
                Ok(())
            })
            .public(),
        );
    }
    let app = b.build().unwrap();
    let built = start.elapsed();
    assert!(built < Duration::from_secs(10), "built in {built:?}");

    for (path, want) in [
        ("/s0", "0:"),
        ("/s9996", "9996:"),
        ("/s1/items/42", "1:42"),
        ("/s9997/items/x%20y", "9997:x y"),
        ("/s2/files/a/b/c.txt", "2:a/b/c.txt"),
        ("/s9999/a/b/c/z/d", "9999:z"),
    ] {
        let r = respond(
            &app,
            format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes(),
        );
        assert_eq!((r.status, r.text()), (200, want), "{path}");
    }
    for path in ["/s1", "/s3/a/b/c/z", "/s10000", "/x"] {
        let r = respond(
            &app,
            format!("GET {path} HTTP/1.1\r\nHost: a\r\n\r\n").as_bytes(),
        );
        assert_eq!(r.status, 404, "{path}");
    }
}
