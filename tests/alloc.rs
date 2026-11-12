//! The warm request path allocates nothing beyond what serve-net itself
//! does: the same requests on a keep-alive connection, once through a bare
//! serve-net handler and once through web-net, counted by a global
//! allocator. One test in this file, so nothing else allocates meanwhile.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use serve_net::testing::TestConnection;
use web_net::{App, Group, get};

struct Counting;

static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

// SAFETY: forwards to the system allocator unchanged; only counts calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is passed through.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is passed through.
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the caller's contract is passed through.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

fn per_request<S: serve_net::HttpService>(conn: &mut TestConnection<S>, req: &[u8]) -> f64 {
    let mut out = Vec::with_capacity(1 << 16);
    for _ in 0..10 {
        out.clear();
        conn.send_into(req, &mut out);
    }
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    // Under serve-net's requests-per-connection cap.
    const N: usize = 80;
    for _ in 0..N {
        out.clear();
        conn.send_into(req, &mut out);
    }
    assert!(
        out.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    (ALLOCATIONS.load(Ordering::Relaxed) - before) as f64 / N as f64
}

#[test]
fn test_warm_pipeline_adds_no_allocation() {
    let app = App::builder()
        .host("example.com")
        .base("/app")
        .route(get("/", |cx| cx.text(200, "home")).public())
        .group(
            Group::at("/users")
                .public()
                .route(get("/:id", |cx| {
                    let ok = cx.param("id").is_ok_and(|id| id == "7");
                    cx.text(200, if ok { "user 7" } else { "other" })
                }))
                .route(get("/:id/posts/:post", |cx| cx.text(200, "post"))),
        )
        .build()
        .unwrap();
    let raw = serve_net::handler(|_req, reply| {
        reply.text(200, "user 7");
    });

    let req = b"GET /app/users/7 HTTP/1.1\r\nHost: Example.COM\r\nAccept: text/html\r\nAccept-Encoding: gzip\r\n\r\n";
    let base = per_request(&mut TestConnection::new(raw), req);
    let web = per_request(&mut TestConnection::new(app), req);
    eprintln!("allocations per request: serve-net alone {base:.2}, through web-net {web:.2}");
    assert!(
        web <= base,
        "web-net adds {:.2} allocations per request ({web:.2} against {base:.2})",
        web - base
    );
}
