//! The connections to the leanVM sidecar, a separate process that proves.
//!
//! [`LeanVmApi`] takes `LeanVmReq` bodies off the spine and frames them onto
//! Unix sockets, one request at a time on each. The sidecar verifies on each
//! connection's own thread and proves one request at a time across them, so
//! verifies run beside a proof. Each response body goes back as a
//! `LeanVmResp`, unparsed, status byte included. Every request is answered:
//! `None` means no answer. `LeanVmHealthEvent` says whether the sidecar can
//! take a request.

mod connection;

use std::{
    fmt::Display,
    mem,
    path::PathBuf,
    time::{Duration, Instant},
};

use connection::Connection;
use flux::spine::SpineAdapter;
use mio::{Events, Interest, Registry, net::UnixStream};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, SilverSpine, TCacheError, TCacheId, TCacheReader,
    TCacheTable, TProducer, TReadMode,
};
use silver_httpcore::TokenRange;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);
/// All the sidecar serves at once: this node is its only client, so no
/// verify waits here behind another.
const CONNECTIONS: usize = 16;

enum Link {
    Down { retry_at: Instant },
    Up(Connection),
}

impl Link {
    fn ready(&self) -> Option<&Connection> {
        match self {
            Self::Up(connection) if connection.is_ready() => Some(connection),
            Self::Up(_) | Self::Down { .. } => None,
        }
    }
}

pub struct LeanVmApi {
    registry: Registry,
    tokens: TokenRange,
    socket: Option<PathBuf>,
    links: [Link; CONNECTIONS],
    reader: TCacheReader,
    answers: Vec<LeanVmResp>,
    ready_published: bool,
    drained: bool,
}

impl LeanVmApi {
    pub const MAX_SOCKETS: usize = CONNECTIONS;

    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        socket: Option<&str>,
        tcaches: TCacheTable,
    ) -> Self {
        Self {
            registry: registry.try_clone().expect("clone the mio registry"),
            tokens,
            socket: socket.map(PathBuf::from),
            links: std::array::from_fn(|_| Link::Down { retry_at: Instant::now() }),
            reader: TCacheReader::new(tcaches),
            answers: Vec::new(),
            ready_published: false,
            drained: true,
        }
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(
            TCacheId::BeaconStateHandoff,
            "leanvm_beacon_state_handoff",
            TReadMode::Sliding,
        )
    }

    /// Sends each request to an idle connection. One waits while every ready
    /// connection is busy, and is answered `None` when none is ready.
    pub fn intake(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.drained {
            self.reader.free();
        } else {
            self.reader.free_undrained();
        }
        self.drained = false;
        while self.can_take() {
            if !adapter.consume_one(|req: LeanVmReq, _| self.start(req)) {
                self.drained = true;
                break;
            }
        }
        self.publish(adapter);
    }

    pub fn spin(
        &mut self,
        adapter: &mut SpineAdapter<SilverSpine>,
        events: &Events,
        producer: &mut TProducer,
    ) {
        for event in events.iter() {
            let Some(index) = self.tokens.offset_of(event.token()).filter(|&i| i < CONNECTIONS)
            else {
                continue;
            };
            if let Link::Up(connection) = &mut self.links[index] &&
                let Err(error) = connection.pump(producer, &mut self.answers)
            {
                self.close(index, error);
            }
        }
        let now = Instant::now();
        for index in 0..CONNECTIONS {
            if let Link::Up(connection) = &self.links[index] &&
                connection.is_overdue(now)
            {
                self.close(index, "the sidecar did not answer in time");
            }
        }
        self.reconnect(now);
        self.publish(adapter);
    }

    fn can_take(&self) -> bool {
        let mut ready = self.links.iter().filter_map(Link::ready).peekable();
        ready.peek().is_none() || ready.any(Connection::is_idle)
    }

    fn start(&mut self, req: LeanVmReq) {
        let idle = self.links.iter().position(|link| link.ready().is_some_and(Connection::is_idle));
        if let Some(index) = idle &&
            let Link::Up(connection) = &mut self.links[index] &&
            connection.load(&mut self.reader, req)
        {
            if let Err(error) = connection.write() {
                self.close(index, error);
            }
        } else {
            self.answers.push(LeanVmResp { request_id: req.request_id, body: None });
        }
    }

    fn reconnect(&mut self, now: Instant) {
        let Some(socket) = &self.socket else { return };
        for (index, link) in self.links.iter_mut().enumerate() {
            let Link::Down { retry_at } = link else { continue };
            if now < *retry_at {
                continue;
            }
            let token = self.tokens.at(index);
            let connected = UnixStream::connect(socket).and_then(|mut stream| {
                let interest = Interest::READABLE | Interest::WRITABLE;
                self.registry.register(&mut stream, token, interest)?;
                Ok(stream)
            });
            *link = match connected {
                Ok(stream) => Link::Up(Connection::new(stream)),
                Err(error) => {
                    silver_log::debug!(%error, "leanvm sidecar connect failed");
                    Link::Down { retry_at: now + RECONNECT_DELAY }
                }
            };
        }
    }

    /// Answers the connection's request in flight `None`.
    fn close(&mut self, index: usize, why: impl Display) {
        silver_log::warn!(%why, index, "leanvm sidecar connection closed");
        let down = Link::Down { retry_at: Instant::now() + RECONNECT_DELAY };
        let Link::Up(mut connection) = mem::replace(&mut self.links[index], down) else { return };
        let _ = self.registry.deregister(&mut connection.stream);
        if let Some(request_id) = connection.request_id() {
            self.answers.push(LeanVmResp { request_id, body: None });
        }
    }

    /// Health before answers, so a reader that sees a disconnect's `None`
    /// answer has its `LeanVmHealthEvent` already published.
    fn publish(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let ready = self.links.iter().any(|link| link.ready().is_some());
        if ready != self.ready_published {
            silver_log::info!(ready, "leanvm sidecar readiness changed");
            self.ready_published = ready;
            adapter.produce(LeanVmHealthEvent { ready });
        }
        for resp in self.answers.drain(..) {
            adapter.produce(resp);
        }
    }
}
