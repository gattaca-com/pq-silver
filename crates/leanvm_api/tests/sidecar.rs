use std::{
    io::{Read, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use flux::{spine::SpineAdapter, tile::Tile};
use silver_common::{
    LeanVmHealthEvent, LeanVmReq, LeanVmResp, SilverSpine, TCache, TCacheId, TCacheProducer,
    TCacheTable, TProducer, test_util::ShmemDir,
};
use silver_httpcore::{Readiness, TokenRange};
use silver_leanvm_api::LeanVmApi;
use tempfile::TempDir;

const CONNECTIONS: usize = LeanVmApi::MAX_SOCKETS;

struct Injector;
impl Tile<SilverSpine> for Injector {
    fn loop_body(&mut self, _: &mut SpineAdapter<SilverSpine>) {}
}

struct Rig {
    _base: ShmemDir,
    _spine: Box<SilverSpine>,
    readiness: Readiness,
    api: LeanVmApi,
    adapter: SpineAdapter<SilverSpine>,
    injector: SpineAdapter<SilverSpine>,
    processing: TProducer,
    handoff: TProducer,
    answers: Vec<(u64, Option<Vec<u8>>)>,
    health: Vec<bool>,
}

impl Rig {
    fn new(socket: Option<&Path>) -> Self {
        let base = ShmemDir::new().unwrap();
        let mut spine = Box::new(SilverSpine::new_with_base_dir(base.path(), None));
        let processing = TCache::producer(TCacheId::BoundaryProcessing, 1 << 24);
        let handoff = TCache::producer(TCacheId::BeaconStateHandoff, 1 << 24);
        let tcaches = TCacheTable::from_iter([processing.cache_ref(), handoff.cache_ref()]);
        let readiness = Readiness::new(4);
        let socket = socket.map(|path| path.to_str().unwrap());
        let mut api = LeanVmApi::new(readiness.registry(), TokenRange::whole(), socket, tcaches);
        api.open_tcaches().unwrap();
        let adapter = SpineAdapter::connect_tile(&Injector, &mut *spine);
        let mut injector = SpineAdapter::connect_tile(&Injector, &mut *spine);
        injector.consume(|_: LeanVmResp, _| {});
        injector.consume(|_: LeanVmHealthEvent, _| {});
        let mut rig = Self {
            _base: base,
            _spine: spine,
            readiness,
            api,
            adapter,
            injector,
            processing,
            handoff,
            answers: Vec::new(),
            health: Vec::new(),
        };
        rig.crank();
        rig
    }

    fn crank(&mut self) {
        self.processing.loop_start();
        self.api.intake(&mut self.adapter);
        self.readiness.wait(Duration::from_millis(1));
        self.api.spin(&mut self.adapter, self.readiness.events(), &mut self.processing);
        let Self { injector, processing, answers, health, .. } = self;
        injector.consume(|resp: LeanVmResp, _| {
            let body = resp.body.map(|read| processing.read_buffer(read).unwrap().to_vec());
            answers.push((resp.request_id, body));
        });
        injector.consume(|resp: LeanVmHealthEvent, _| health.push(resp.ready));
    }

    fn wait_until(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !done(self) {
            assert!(Instant::now() < deadline, "timeout: {what}");
            self.crank();
        }
    }

    fn wait_ready(&mut self) {
        self.wait_until("ready", |rig| rig.health.last() == Some(&true));
    }

    /// Every connection is accepted, and long enough has passed to read the
    /// hello each was sent at once: no connection is left mid-handshake.
    fn wait_all_ready(&mut self, sidecar: &FakeSidecar) {
        self.wait_until("every connection accepted", |_| sidecar.accepted() >= CONNECTIONS);
        let settled = Instant::now() + Duration::from_millis(100);
        self.wait_until("the hellos read", |_| Instant::now() >= settled);
    }

    fn request(&mut self, request_id: u64, body: &[u8]) {
        let body = self.handoff.write_with(body.len(), |out| out.copy_from_slice(body)).unwrap();
        self.handoff.loop_start();
        self.injector.produce(LeanVmReq { request_id, body });
    }

    fn answer(&mut self, request_id: u64) -> Option<Vec<u8>> {
        self.wait_until("an answer", |rig| rig.answers.iter().any(|(id, _)| *id == request_id));
        self.answers.iter().find(|(id, _)| *id == request_id).unwrap().1.clone()
    }
}

struct FakeSidecar {
    _dir: TempDir,
    path: PathBuf,
    accepted: Arc<AtomicUsize>,
}

impl FakeSidecar {
    fn spawn(script: impl Fn(UnixStream, usize) + Send + Sync + 'static) -> Self {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("sidecar.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let script = Arc::new(script);
        thread::spawn({
            let accepted = accepted.clone();
            move || {
                for stream in listener.incoming() {
                    let index = accepted.fetch_add(1, Ordering::SeqCst);
                    let script = script.clone();
                    thread::spawn(move || script(stream.unwrap(), index));
                }
            }
        });
        Self { _dir: dir, path, accepted }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

fn hello(magic: &[u8], max_request_len: u64) -> Vec<u8> {
    let mut body = magic.to_vec();
    body.extend(1u32.to_le_bytes());
    body.extend(max_request_len.to_le_bytes());
    for field in [b"leanvm-v1".as_slice(), b"experimental"] {
        body.extend((field.len() as u64).to_le_bytes());
        body.extend(field);
    }
    body
}

fn send_frame(stream: &mut UnixStream, body: &[u8]) {
    stream.write_all(&(body.len() as u64).to_le_bytes()).unwrap();
    stream.write_all(body).unwrap();
}

fn read_request(stream: &mut UnixStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header).ok()?;
    let mut body = vec![0u8; u64::from_le_bytes(header) as usize];
    stream.read_exact(&mut body).ok()?;
    Some(body)
}

#[test]
fn a_good_hello_makes_the_connection_ready() {
    // The sidecar stays connected: a close right after the hello could read
    // as going down before the test sees ready.
    let sidecar = FakeSidecar::spawn(|mut stream, _| {
        send_frame(&mut stream, &hello(b"leanvmsc", 64));
        let _ = stream.read_to_end(&mut Vec::new());
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_ready();
    assert_eq!(rig.health, [true]);
}

#[test]
fn a_bad_hello_closes_the_connection() {
    let closed = Arc::new(AtomicBool::new(false));
    let sidecar = FakeSidecar::spawn({
        let closed = closed.clone();
        move |mut stream, _| {
            send_frame(&mut stream, &hello(b"leanvmXX", 64));
            stream.read_to_end(&mut Vec::new()).unwrap();
            closed.store(true, Ordering::SeqCst);
        }
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_until("the sidecar sees the close", |_| closed.load(Ordering::SeqCst));
    assert!(rig.health.is_empty());
}

#[test]
fn a_request_goes_out_framed_and_the_response_comes_back_whole() {
    let sidecar = FakeSidecar::spawn(|mut stream, _| {
        send_frame(&mut stream, &hello(b"leanvmsc", 64));
        while let Some(request) = read_request(&mut stream) {
            send_frame(&mut stream, &[&[7], request.as_slice()].concat());
        }
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_ready();
    rig.request(1, &[1, 2, 3]);
    assert_eq!(rig.answer(1), Some(vec![7, 1, 2, 3]));
    rig.request(2, &[4; 65]);
    assert_eq!(rig.answer(2), None, "over the hello's max request length");
    rig.request(3, &[5]);
    assert_eq!(rig.answer(3), Some(vec![7, 5]));
    // A reopened connection would pass the count and never come back to it.
    rig.wait_until("every connection up, none reopened", |_| sidecar.accepted() == CONNECTIONS);
}

/// Each answer waits until both requests have arrived, which one connection
/// could not do: it sends the second only after the first is answered.
#[test]
fn requests_on_separate_connections_are_in_flight_at_once() {
    let arrived = Arc::new(AtomicUsize::new(0));
    let sidecar = FakeSidecar::spawn({
        let arrived = arrived.clone();
        move |mut stream, _| {
            send_frame(&mut stream, &hello(b"leanvmsc", 64));
            while let Some(request) = read_request(&mut stream) {
                arrived.fetch_add(1, Ordering::SeqCst);
                while arrived.load(Ordering::SeqCst) < 2 {
                    thread::sleep(Duration::from_millis(1));
                }
                send_frame(&mut stream, &request);
            }
        }
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_ready();
    rig.request(1, &[1]);
    rig.request(2, &[2]);
    assert_eq!(rig.answer(1), Some(vec![1]));
    assert_eq!(rig.answer(2), Some(vec![2]));
}

/// A fake sidecar whose first request served, on whichever connection, gets
/// `misbehave`; every other one is echoed.
fn first_request_misbehaves(
    misbehave: impl Fn(&mut UnixStream) + Send + Sync + 'static,
) -> FakeSidecar {
    let first = Arc::new(AtomicBool::new(true));
    FakeSidecar::spawn(move |mut stream, _| {
        send_frame(&mut stream, &hello(b"leanvmsc", 64));
        while let Some(request) = read_request(&mut stream) {
            if first.swap(false, Ordering::SeqCst) {
                return misbehave(&mut stream);
            }
            send_frame(&mut stream, &request);
        }
    })
}

/// The connection that failed is replaced; the others serve meanwhile, so the
/// sidecar stays ready.
fn assert_replaced(rig: &mut Rig, sidecar: &FakeSidecar) {
    rig.request(2, &[2]);
    assert_eq!(rig.answer(2), Some(vec![2]));
    rig.wait_until("the connection replaced", |_| sidecar.accepted() == CONNECTIONS + 1);
    assert_eq!(rig.health, [true]);
}

#[test]
fn a_hang_up_mid_request_answers_none_and_reconnects() {
    let sidecar = first_request_misbehaves(|_| {});
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_all_ready(&sidecar);
    rig.request(1, &[1]);
    assert_eq!(rig.answer(1), None);
    assert_replaced(&mut rig, &sidecar);
}

#[test]
fn an_oversized_response_frame_closes_the_connection() {
    let sidecar = first_request_misbehaves(|stream| {
        stream.write_all(&((8u64 << 20) + 1).to_le_bytes()).unwrap();
        read_request(stream);
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_all_ready(&sidecar);
    rig.request(1, &[1]);
    assert_eq!(rig.answer(1), None);
    assert_replaced(&mut rig, &sidecar);
}

#[test]
fn a_response_that_arrives_while_the_request_is_written_is_delivered() {
    let sidecar = FakeSidecar::spawn(|mut stream, _| {
        send_frame(&mut stream, &hello(b"leanvmsc", 8 << 20));
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).unwrap();
        send_frame(&mut stream, &[7]);
        let mut body = vec![0u8; u64::from_le_bytes(header) as usize];
        stream.read_exact(&mut body).unwrap();
        while read_request(&mut stream).is_some() {}
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_ready();
    rig.request(1, &vec![1; 4 << 20]);
    assert_eq!(rig.answer(1), Some(vec![7]));
}

#[test]
fn a_sidecar_that_never_answers_is_dropped_after_the_timeout() {
    let sidecar = first_request_misbehaves(|stream| while read_request(stream).is_some() {});
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_all_ready(&sidecar);
    rig.request(1, &[1]);
    assert_eq!(rig.answer(1), None);
    assert_replaced(&mut rig, &sidecar);
}

#[test]
fn a_byte_while_idle_closes_the_connection() {
    let sidecar = FakeSidecar::spawn(|mut stream, index| {
        send_frame(&mut stream, &hello(b"leanvmsc", 64));
        if index == 0 {
            thread::sleep(Duration::from_millis(200));
            stream.write_all(&[0]).unwrap();
        }
        while read_request(&mut stream).is_some() {}
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_until("the connection replaced", |_| sidecar.accepted() == CONNECTIONS + 1);
    assert_eq!(rig.health, [true]);
}

/// Health goes down only with the last connection, and up with the first.
#[test]
fn the_sidecar_is_down_once_every_connection_is() {
    let sidecar = FakeSidecar::spawn(|mut stream, index| {
        send_frame(&mut stream, &hello(b"leanvmsc", 64));
        if index < CONNECTIONS {
            thread::sleep(Duration::from_millis(200));
            return;
        }
        while read_request(&mut stream).is_some() {}
    });
    let mut rig = Rig::new(Some(&sidecar.path));
    rig.wait_until("down, then ready again", |rig| rig.health == [true, false, true]);
}

#[test]
fn without_a_socket_every_request_is_answered_none() {
    let mut rig = Rig::new(None);
    rig.request(1, &[1]);
    assert_eq!(rig.answer(1), None);
    assert!(rig.health.is_empty());
}

#[test]
#[ignore = "needs a running leanvm-sidecar: set LEANVM_SIDECAR_SOCKET"]
fn a_real_sidecar_has_nothing_to_publish_for_zero_signatures() {
    let socket = std::env::var("LEANVM_SIDECAR_SOCKET").expect("LEANVM_SIDECAR_SOCKET");
    let mut rig = Rig::new(Some(Path::new(&socket)));
    rig.wait_ready();
    let mut body = vec![1, 2];
    body.extend([0u8; 8 * 4]);
    body.push(0);
    rig.request(1, &body);
    let response = rig.answer(1).expect("a response");
    assert_eq!(response[0], 1, "invalid input: nothing to publish");
}
