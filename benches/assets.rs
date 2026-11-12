//! What a static file costs per request: a small file, the same with a
//! precompressed variant asked for, a 304, and a large file in parts.
//!
//! Uses only the API that 0.9 and 0.10 share, so the same file runs on both
//! sides of an A/B.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use serve_net::HttpService;
use serve_net::testing::TestConnection;
use web_net::{App, Assets};

/// Requests per connection, under serve-net's per-connection cap.
const PER_CONN: u64 = 50;

#[derive(Clone)]
struct Shared(Arc<App>);

impl HttpService for Shared {
    fn call(
        &self,
        request: &serve_net::HttpRequest<'_>,
        env: &serve_net::Envelope,
        reply: &mut serve_net::HttpReply,
    ) -> serve_net::Outcome {
        self.0.call(request, env, reply)
    }

    fn done(&self, env: &serve_net::Envelope, finished: &serve_net::Finished) {
        self.0.done(env, finished);
    }
}

fn run(service: &Shared, req: &[u8], iters: u64) -> Duration {
    let mut total = Duration::ZERO;
    let mut done = 0;
    let mut out = Vec::with_capacity(4 << 20);
    while done < iters {
        let mut conn = TestConnection::new(service.clone());
        let n = PER_CONN.min(iters - done);
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

fn folder() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("web-net-bench-assets-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("bench folder");
    std::fs::write(dir.join("small.css"), vec![b'a'; 10 << 10]).expect("small file");
    std::fs::write(dir.join("large.bin"), vec![7u8; 2 << 20]).expect("large file");
    dir
}

fn benches(c: &mut Criterion) {
    let dir = folder();
    let app = Shared(Arc::new(
        App::builder()
            .host("localhost")
            .assets(Assets::new("/s", &dir))
            .build()
            .expect("bench app"),
    ));
    let small = b"GET /s/small.css HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let br = b"GET /s/small.css HTTP/1.1\r\nHost: localhost\r\nAccept-Encoding: br, gzip\r\n\r\n";
    let large = b"GET /s/large.bin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    // The 304 needs the file's own tag.
    let mut probe = TestConnection::new(app.clone());
    let mut out = Vec::new();
    probe.send_into(small, &mut out);
    let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
    let tag = text
        .lines()
        .find_map(|l| l.strip_prefix("etag: "))
        .expect("an etag")
        .trim()
        .to_owned();
    let not_modified =
        format!("GET /s/small.css HTTP/1.1\r\nHost: localhost\r\nIf-None-Match: {tag}\r\n\r\n");

    let mut g = c.benchmark_group("assets");
    g.bench_function("small_10k", |b| b.iter_custom(|n| run(&app, small, n)));
    g.bench_function("small_10k_accepts_br", |b| {
        b.iter_custom(|n| run(&app, br, n))
    });
    g.bench_function("not_modified", |b| {
        b.iter_custom(|n| run(&app, not_modified.as_bytes(), n))
    });
    g.sample_size(10);
    g.bench_function("large_2m", |b| b.iter_custom(|n| run(&app, large, n)));
    g.finish();
    let _ = std::fs::remove_dir_all(&dir);
}

criterion_group!(group, benches);
criterion_main!(group);
