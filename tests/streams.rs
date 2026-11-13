//! Large files in parts over real sockets: a download in progress keeps its
//! bytes whatever other downloads do on its worker.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serve_net::{ListenerSpec, Server, Workers};
use web_net::{App, Assets};

const SIZE: usize = 48 << 20; // far more than loopback buffers hold
const BLOCK: usize = 64 << 10;

/// Each 64 KiB block holds its own index, so a misplaced block shows.
fn content() -> Vec<u8> {
    let mut v = vec![0u8; SIZE];
    for (i, chunk) in v.chunks_mut(BLOCK).enumerate() {
        let tag = (i as u32).to_le_bytes();
        for (j, b) in chunk.iter_mut().enumerate() {
            *b = tag[j % 4];
        }
    }
    v
}

fn read_head(s: &mut TcpStream) -> Vec<u8> {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        s.read_exact(&mut b).unwrap();
        head.push(b[0]);
    }
    head
}

/// A chunked body, and whether it ended with the terminating chunk.
fn read_chunked(s: &mut TcpStream) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            if s.read(&mut b).unwrap_or(0) == 0 {
                return (body, false);
            }
            line.push(b[0]);
            if line.ends_with(b"\r\n") {
                break;
            }
        }
        let text = std::str::from_utf8(&line[..line.len() - 2]).unwrap();
        let n = usize::from_str_radix(text.trim(), 16).unwrap();
        if n == 0 {
            let mut end = [0u8; 2];
            let ok = s.read_exact(&mut end).is_ok() && &end == b"\r\n";
            return (body, ok);
        }
        let mut chunk = vec![0u8; n + 2];
        if s.read_exact(&mut chunk).is_err() {
            return (body, false);
        }
        body.extend_from_slice(&chunk[..n]);
    }
}

#[test]
fn test_download_in_progress_survives_300_dropped_downloads() {
    let dir = std::env::temp_dir().join(format!("web-net-streams-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let data = content();
    std::fs::write(dir.join("big.bin"), &data).unwrap();

    let app = App::builder()
        .assets(Assets::new("/s", &dir))
        .build()
        .unwrap();
    let running = Server::builder()
        .listener(ListenerSpec::tcp("web", "127.0.0.1:0"))
        .workers(Workers::reactor(1))
        .serve(app)
        .unwrap();
    let addr = running.local_addr().unwrap();
    let req = b"GET /s/big.bin HTTP/1.1\r\nHost: localhost\r\n\r\n";

    // The download that must stay whole: its head arrives, then it pauses.
    let mut victim = TcpStream::connect(addr).unwrap();
    victim
        .set_read_timeout(Some(Duration::from_secs(60)))
        .unwrap();
    victim.write_all(req).unwrap();
    let head = read_head(&mut victim);
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );

    // 300 other downloads on the same worker, dropped after their heads.
    // Each is answered (200, or 503 when the worker is full), never
    // with a reply inside another.
    for _ in 0..300 {
        let mut s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        s.write_all(req).unwrap();
        let h = read_head(&mut s);
        assert!(
            h.starts_with(b"HTTP/1.1 200") || h.starts_with(b"HTTP/1.1 503"),
            "{}",
            String::from_utf8_lossy(&h)
        );
        drop(s);
    }

    let (body, clean) = read_chunked(&mut victim);
    let first_bad = body
        .chunks(BLOCK)
        .zip(data.chunks(BLOCK))
        .position(|(a, b)| a != b);
    running.drain(Duration::from_secs(2));
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(first_bad, None, "a block of the download was replaced");
    assert!(clean, "the download did not end");
    assert_eq!(body.len(), data.len());
}
