//! What web-net costs per request on top of serve-net.
//!
//! Every case sends the same kind of request on a keep-alive test connection
//! (no sockets), so the difference between a case and `serve_net_alone` is
//! web-net's own work: site, path, route, gate, handler context, security
//! headers, and the copy of the held reply.

use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use serve_net::HttpService;
use serve_net::testing::TestConnection;
use web_net::{App, get};

/// Requests per connection, under serve-net's per-connection cap.
const PER_CONN: u64 = 50;

fn run<S: HttpService + Clone>(service: &S, req: &[u8], iters: u64) -> Duration {
    let mut total = Duration::ZERO;
    let mut done = 0;
    let mut out = Vec::with_capacity(1 << 16);
    while done < iters {
        let mut conn = TestConnection::new(service.clone());
        let n = PER_CONN.min(iters - done);
        // Warm the connection's buffers outside the timing.
        out.clear();
        conn.send_into(req, &mut out);
        let start = Instant::now();
        for _ in 0..n {
            out.clear();
            conn.send_into(black_box(req), &mut out);
        }
        total += start.elapsed();
        done += n;
    }
    total
}

struct Shared<T>(std::sync::Arc<T>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(std::sync::Arc::clone(&self.0))
    }
}

impl<T: HttpService> HttpService for Shared<T> {
    fn call(
        &self,
        request: &serve_net::HttpRequest<'_>,
        env: &serve_net::Envelope,
        reply: &mut serve_net::HttpReply,
    ) -> serve_net::Outcome {
        self.0.call(request, env, reply)
    }
}

fn app(routes: usize) -> Shared<App> {
    app_with(routes, web_net::SecurityHeaders::default())
}

fn app_with(routes: usize, security: web_net::SecurityHeaders) -> Shared<App> {
    let mut b = App::builder()
        .host("example.com")
        .security_headers(security);
    for i in 0..routes {
        b = b.route(get(format!("/section-{i}/items/:id"), |cx| cx.text(200, "item")).public());
    }
    b = b.route(get("/users/:id", |cx| cx.text(200, "user 7")).public());
    Shared(std::sync::Arc::new(b.build().expect("bench app")))
}

fn benches(c: &mut Criterion) {
    let raw = Shared(std::sync::Arc::new(serve_net::handler(|_req, reply| {
        reply.text(200, "user 7");
    })));
    let small = app(10);
    let large = app(10_000);
    let bare = app_with(10, web_net::SecurityHeaders::none());
    let user = b"GET /users/7 HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n";
    let deep = b"GET /section-9876/items/42 HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let dotted = b"GET /users/./7/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let missing = b"GET /nothing/here HTTP/1.1\r\nHost: example.com\r\n\r\n";

    let mut g = c.benchmark_group("request");
    g.bench_function("serve_net_alone", |b| b.iter_custom(|n| run(&raw, user, n)));
    g.bench_function("web_net_10_routes", |b| {
        b.iter_custom(|n| run(&small, user, n))
    });
    g.bench_function("web_net_no_security_headers", |b| {
        b.iter_custom(|n| run(&bare, user, n))
    });
    g.bench_function("web_net_10k_routes", |b| {
        b.iter_custom(|n| run(&large, user, n))
    });
    g.bench_function("web_net_10k_routes_deep", |b| {
        b.iter_custom(|n| run(&large, deep, n))
    });
    g.bench_function("web_net_redirect", |b| {
        b.iter_custom(|n| run(&small, dotted, n))
    });
    g.bench_function("web_net_404", |b| {
        b.iter_custom(|n| run(&small, missing, n))
    });
    g.finish();
}

criterion_group!(web, benches);
criterion_main!(web);
