//! The connection to the leanVM sidecar, a separate process that proves.
//!
//! [`LeanVmApi`] takes `LeanVmReq` bodies off the spine and frames them onto
//! a Unix socket, one request at a time. Each response body goes back as a
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
use mio::{Events, Interest, Registry, Token, net::UnixStream};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, SilverSpine, TCacheError, TCacheId, TCacheReader,
    TCacheTable, TProducer, TReadMode,
};
use silver_httpcore::TokenRange;

const RECONNECT_DELAY: Duration = Duration::from_secs(1);

enum Link {
    Down { retry_at: Instant },
    Up(Connection),
}

pub struct LeanVmApi {
    registry: Registry,
    token: Token,
    socket: Option<PathBuf>,
    link: Link,
    reader: TCacheReader,
    answers: Vec<LeanVmResp>,
    ready_published: bool,
    drained: bool,
}

impl LeanVmApi {
    pub const MAX_SOCKETS: usize = 1;

    pub fn new(
        registry: &Registry,
        tokens: TokenRange,
        socket: Option<&str>,
        tcaches: TCacheTable,
    ) -> Self {
        Self {
            registry: registry.try_clone().expect("clone the mio registry"),
            token: tokens.at(0),
            socket: socket.map(PathBuf::from),
            link: Link::Down { retry_at: Instant::now() },
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

    /// Sends the next request once the connection is idle. A request that
    /// meets a connection that is not ready is answered `None`.
    pub fn intake(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        if self.drained {
            self.reader.free();
        } else {
            self.reader.free_undrained();
        }
        self.drained = false;
        while !self.is_busy() {
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
        let token = self.token;
        for _ in events.iter().filter(|event| event.token() == token) {
            if let Link::Up(connection) = &mut self.link &&
                let Err(error) = connection.pump(producer, &mut self.answers)
            {
                self.close(error);
            }
        }
        if let Link::Up(connection) = &self.link &&
            connection.is_overdue(Instant::now())
        {
            self.close("the sidecar did not answer in time");
        }
        self.reconnect();
        self.publish(adapter);
    }

    fn is_busy(&self) -> bool {
        matches!(&self.link, Link::Up(connection) if connection.request_id().is_some())
    }

    fn start(&mut self, req: LeanVmReq) {
        if let Link::Up(connection) = &mut self.link &&
            connection.is_idle() &&
            connection.load(&mut self.reader, req)
        {
            if let Err(error) = connection.write() {
                self.close(error);
            }
        } else {
            self.answers.push(LeanVmResp { request_id: req.request_id, body: None });
        }
    }

    fn reconnect(&mut self) {
        let (Link::Down { retry_at }, Some(socket)) = (&self.link, &self.socket) else {
            return;
        };
        if Instant::now() < *retry_at {
            return;
        }
        let connected = UnixStream::connect(socket).and_then(|mut stream| {
            let interest = Interest::READABLE | Interest::WRITABLE;
            self.registry.register(&mut stream, self.token, interest)?;
            Ok(stream)
        });
        self.link = match connected {
            Ok(stream) => Link::Up(Connection::new(stream)),
            Err(error) => {
                silver_log::debug!(%error, "leanvm sidecar connect failed");
                Link::Down { retry_at: Instant::now() + RECONNECT_DELAY }
            }
        };
    }

    /// Answers the request in flight `None`.
    fn close(&mut self, why: impl Display) {
        silver_log::warn!(%why, "leanvm sidecar connection closed");
        let down = Link::Down { retry_at: Instant::now() + RECONNECT_DELAY };
        let Link::Up(mut connection) = mem::replace(&mut self.link, down) else { return };
        let _ = self.registry.deregister(&mut connection.stream);
        if let Some(request_id) = connection.request_id() {
            self.answers.push(LeanVmResp { request_id, body: None });
        }
    }

    /// Health before answers, so a reader that sees a disconnect's `None`
    /// answer has its `LeanVmHealthEvent` already published.
    fn publish(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let ready = matches!(&self.link, Link::Up(connection) if connection.is_ready());
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
