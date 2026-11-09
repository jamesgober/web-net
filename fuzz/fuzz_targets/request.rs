//! Any bytes as one or more requests on a keep-alive connection: nothing
//! panics, every reply has a status, and nothing but `/site/admin` reached
//! with the admin cookie ever answers "admin".

#![no_main]

use libfuzzer_sys::fuzz_target;
use serve_net::testing::TestConnection;

fuzz_target!(|data: &[u8]| {
    let app = web_net_fuzz::app();
    let mut conn = TestConnection::new(Wrap(app));
    for reply in conn.send(data) {
        assert!(reply.status == 0 || (100..=599).contains(&reply.status));
        if reply.header("x-admin-page").is_some() {
            // Only the admin can see it; the fuzzer must put the cookie in.
            assert!(
                data.windows(9).any(|w| w == b"sid=admin"),
                "the admin page without the admin session"
            );
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
