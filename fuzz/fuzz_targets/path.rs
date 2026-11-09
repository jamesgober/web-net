//! Any request target: a redirect to the canonical path is never followed
//! by another redirect (no loops, one canonical spelling), and the admin page
//! is reached by no spelling without the admin session.

#![no_main]

use libfuzzer_sys::fuzz_target;
use serve_net::testing::respond;

fn get(target: &[u8], cookie: &str) -> serve_net::testing::TestReply {
    let mut raw = b"GET ".to_vec();
    raw.extend_from_slice(target);
    raw.extend_from_slice(b" HTTP/1.1\r\nHost: a\r\n");
    raw.extend_from_slice(cookie.as_bytes());
    raw.extend_from_slice(b"\r\n");
    respond(&Wrap(web_net_fuzz::app()), &raw)
}

fuzz_target!(|data: &[u8]| {
    // Keep to bytes a request line can carry; the parser refuses the rest.
    if data.is_empty() || data.iter().any(|&b| b <= b' ' || b >= 0x7f) {
        return;
    }
    let mut target = b"/site".to_vec();
    if data[0] != b'/' {
        target.push(b'/');
    }
    target.extend_from_slice(data);

    let first = get(&target, "");
    assert!(first.header("x-admin-page").is_none(), "admin reached as a guest");
    if matches!(first.status, 301 | 308) {
        let loc = first.header("location").expect("a redirect has a location").to_vec();
        if loc.starts_with(b"/") {
            let second = get(&loc, "");
            assert!(
                !matches!(second.status, 301 | 308),
                "a canonical redirect was redirected again: {:?} -> {:?}",
                String::from_utf8_lossy(&target),
                String::from_utf8_lossy(&loc)
            );
            assert!(second.header("x-admin-page").is_none(), "admin reached as a guest");
        }
    }
});

struct Wrap(&'static web_net::App<web_net_fuzz::FuzzGate>);

impl serve_net::HttpService for Wrap {
    fn call(
        &self,
        request: &serve_net::HttpRequest<'_>,
        env: &serve_net::Envelope,
        reply: &mut serve_net::HttpReply,
    ) -> serve_net::Outcome {
        self.0.respond(request, env, reply)
    }
}
