use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::Arc,
    thread,
    time::Duration,
};

use crate::beacon_link::event_stream::tests::EVENTS_ROUTE;

/// Answers each request on one connection from `routes`, by path. The events
/// route streams its body as one chunk and stays open. A connection idle for
/// `idle` is closed, as a node's keep-alive timeout closes it.
pub fn stub_node(routes: Vec<(&'static str, String)>, idle: Option<Duration>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let routes = Arc::new(routes);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let routes = Arc::clone(&routes);
            let stream = stream.unwrap();
            stream.set_read_timeout(idle).unwrap();
            thread::spawn(move || serve(stream, &routes));
        }
    });
    url
}

fn serve(mut stream: TcpStream, routes: &[(&'static str, String)]) {
    let mut pending = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let Ok(n) = stream.read(&mut buf) else { return };
        if n == 0 {
            return;
        }
        pending.extend_from_slice(&buf[..n]);
        while let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&pending[..end]).into_owned();
            let body_len = head
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|len| len.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if pending.len() < end + 4 + body_len {
                break;
            }
            pending.drain(..end + 4 + body_len);
            let path = head.split(' ').nth(1).unwrap_or_default();
            let body = routes.iter().find(|(p, _)| *p == path).map(|(_, b)| b.as_str());
            let response = match body {
                Some(events) if path == EVENTS_ROUTE => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{events}\r\n",
                    events.len()
                ),
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ),
                None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".into(),
            };
            if stream.write_all(response.as_bytes()).is_err() {
                return;
            }
        }
    }
}
