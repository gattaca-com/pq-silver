use std::{
    io::{self, ErrorKind, Read, Write},
    time::{Duration, Instant},
};

use mio::net::UnixStream;
use silver_common::{LeanVmReq, LeanVmResp, TCacheProducer, TCacheReader, TProducer};

/// A proof takes 1-2 s. This bound only frees a sidecar that hangs without
/// closing; a response a mainnet slot late helps no aggregation.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(12);
const FRAME_HEADER_SIZE: usize = 8;
const MAX_HELLO_SIZE: usize = 256;
const MAX_FRAME_SIZE: usize = 8 << 20;
const READ_CHUNK_SIZE: usize = 32 << 10;
const MAGIC: &[u8] = b"leanvmsc";
const VERSION: u32 = 1;
const VERIFIER_ID: &[u8] = b"leanvm-v1";

enum Phase {
    Hello,
    Idle,
    Busy { request_id: u64, written: usize, deadline: Instant },
}

/// One connected socket and its framing. `read_buf` holds at most one frame
/// and one read chunk, and nothing while idle.
pub(crate) struct Connection {
    pub(crate) stream: UnixStream,
    phase: Phase,
    /// From the hello; 0 before it.
    max_request_len: u64,
    read_buf: Vec<u8>,
    write_buf: Vec<u8>,
}

impl Connection {
    pub(crate) fn new(stream: UnixStream) -> Self {
        Self {
            stream,
            phase: Phase::Hello,
            max_request_len: 0,
            read_buf: Vec::new(),
            write_buf: Vec::new(),
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        !matches!(self.phase, Phase::Hello)
    }

    pub(crate) fn is_idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }

    pub(crate) fn request_id(&self) -> Option<u64> {
        match self.phase {
            Phase::Busy { request_id, .. } => Some(request_id),
            Phase::Hello | Phase::Idle => None,
        }
    }

    /// Frames `req`'s body for sending, if it is still in the tcache and
    /// within the hello's max request length.
    pub(crate) fn load(&mut self, reader: &mut TCacheReader, req: LeanVmReq) -> bool {
        debug_assert!(self.is_idle(), "one request at a time");
        let request_id = req.request_id;
        if !reader.is_open(req.body.id()) {
            silver_log::error!(request_id, "leanvm request outside the opened tcaches");
            return false;
        }
        let acquired = reader.acquire(req.body);
        let Ok((body, _)) = acquired.buffer() else {
            silver_log::warn!(request_id, "leanvm request lapped in the tcache");
            return false;
        };
        if body.len() as u64 > self.max_request_len {
            silver_log::warn!(request_id, len = body.len(), "leanvm request too large");
            return false;
        }
        self.write_buf.clear();
        self.write_buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        self.write_buf.extend_from_slice(body);
        if acquired.revalidate().is_err() {
            return false;
        }
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        self.phase = Phase::Busy { request_id, written: 0, deadline };
        true
    }

    /// A request out past its deadline. Its response could still arrive and
    /// be taken for the next request's, so the caller must close.
    pub(crate) fn is_overdue(&self, now: Instant) -> bool {
        matches!(self.phase, Phase::Busy { deadline, .. } if now >= deadline)
    }

    /// Writes what is pending, reads what arrived, then takes a whole frame
    /// off `read_buf`: the hello, or the response once the request is out. A
    /// response goes into `producer`, and its `LeanVmResp` into `answers`.
    pub(crate) fn pump(
        &mut self,
        producer: &mut TProducer,
        answers: &mut Vec<LeanVmResp>,
    ) -> io::Result<()> {
        self.write()?;
        let hung_up = self.read()?;
        self.advance(producer, answers)?;
        if hung_up {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "the sidecar hung up"));
        }
        Ok(())
    }

    pub(crate) fn write(&mut self) -> io::Result<()> {
        let Phase::Busy { written, .. } = &mut self.phase else { return Ok(()) };
        while *written < self.write_buf.len() {
            match self.stream.write(&self.write_buf[*written..]) {
                Ok(0) => return Err(ErrorKind::WriteZero.into()),
                Ok(sent) => *written += sent,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// True once the sidecar hung up. Each chunk is checked against the
    /// frame bound before the next is read.
    fn read(&mut self) -> io::Result<bool> {
        let mut chunk = [0u8; READ_CHUNK_SIZE];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => return Ok(true),
                Ok(read) => {
                    self.read_buf.extend_from_slice(&chunk[..read]);
                    self.frame()?;
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => return Ok(false),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// The body of the one frame in `read_buf`, or `None` while it is
    /// incomplete.
    fn frame(&self) -> io::Result<Option<&[u8]>> {
        let cap = match self.phase {
            Phase::Hello => MAX_HELLO_SIZE,
            Phase::Busy { .. } => MAX_FRAME_SIZE,
            Phase::Idle if self.read_buf.is_empty() => return Ok(None),
            Phase::Idle => return Err(invalid("bytes while idle")),
        };
        let Some((header, rest)) = self.read_buf.split_first_chunk::<FRAME_HEADER_SIZE>() else {
            return Ok(None);
        };
        let len = u64::from_le_bytes(*header);
        if len > cap as u64 {
            return Err(invalid("frame too large"));
        }
        match rest.len().cmp(&(len as usize)) {
            std::cmp::Ordering::Less => Ok(None),
            std::cmp::Ordering::Equal => Ok(Some(rest)),
            std::cmp::Ordering::Greater => Err(invalid("bytes after the frame")),
        }
    }

    fn advance(
        &mut self,
        producer: &mut TProducer,
        answers: &mut Vec<LeanVmResp>,
    ) -> io::Result<()> {
        match self.phase {
            Phase::Hello => {
                let Some(hello) = self.frame()? else { return Ok(()) };
                let max_request_len =
                    parse_hello(hello).ok_or_else(|| invalid("incompatible hello"))?;
                self.max_request_len = max_request_len;
                self.read_buf.clear();
                self.phase = Phase::Idle;
            }
            Phase::Busy { request_id, written, .. } if written == self.write_buf.len() => {
                let Some(body) = self.frame()? else { return Ok(()) };
                let body = producer.write_with(body.len(), |out| out.copy_from_slice(body));
                if body.is_none() {
                    silver_log::error!(request_id, "boundary tcache full; leanvm response dropped");
                }
                answers.push(LeanVmResp { request_id, body });
                self.read_buf.clear();
                self.phase = Phase::Idle;
            }
            Phase::Idle | Phase::Busy { .. } => {}
        }
        Ok(())
    }
}

fn invalid(why: &'static str) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, why)
}

/// The longest request the hello allows, in bytes, if its magic, version and
/// verifier are the ones this client speaks.
fn parse_hello(body: &[u8]) -> Option<u64> {
    let rest = body.strip_prefix(MAGIC)?;
    let (version, rest) = rest.split_first_chunk::<4>()?;
    let (max_request_len, rest) = rest.split_first_chunk::<8>()?;
    let rest = rest.strip_prefix(&(VERIFIER_ID.len() as u64).to_le_bytes())?;
    rest.starts_with(VERIFIER_ID).then_some(())?;
    (u32::from_le_bytes(*version) == VERSION).then(|| u64::from_le_bytes(*max_request_len))
}
