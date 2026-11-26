//! The leanVM tile proves aggregates in this process. `beacon_state`
//! verifies proofs where they arrive.
//!
//! [`LeanVmTile`] consumes `LeanVmReq` messages from the spine and answers
//! each with a `LeanVmResp`. The request tcache holds signed claims and child
//! proofs. The response tcache holds the proven claims and proof bytes.
//! `LeanVmReady` announces the prover before its first answer.
//!
//! The tile's thread proves. leanVM's pool runs the thread that calls
//! `aggregate` as its worker 0, so the tile's core is a prover core, and the
//! pool's other workers run on the rest of the prover cores. A proof blocks
//! the tile for its duration: requests arriving during it are taken once it
//! ends.

#[cfg(test)]
mod tests;

use std::collections::{HashSet, VecDeque};

use flux::{spine::SpineAdapter, tile::Tile, utils::try_thread_boot};
use flux_profiler::timed;
use lean_vm::{
    AggregateClaims, AggregateError, AggregateProof, OutputClaims,
    lean_xmss::{self, LeanXmssPublicKey, LeanXmssSignature},
};
use silver_common::{
    IngestionTime, LeanVmReady, LeanVmReq, LeanVmResp, RefusalCode, SilverSpine, TCacheError,
    TCacheId, TCacheProducer, TCacheReader, TCacheTable, TProducer, TReadMode,
    leanvm::{
        Claim, MAX_PROOF_CLAIMS, MAX_PROOFS, MAX_STARK_PROOF_SIZE, ProofBody, ProofLen,
        RequestBody, SIGNED_CLAIM_SIZE, XMSS_SIGNATURE_SIZE,
    },
};

/// Aggregates taken off the spine and waiting for the prover. `beacon_state`
/// keeps one in flight, so a full queue means it lost track; past it each
/// request is answered with `NoAnswer`.
const MAX_QUEUED_AGGREGATES: usize = 16;
const LOG_INV_RATE: usize = 2;

const _: () = {
    assert!(
        SIGNED_CLAIM_SIZE == lean_xmss::PUB_KEY_SIZE + lean_xmss::MESSAGE_LEN + lean_xmss::SIG_SIZE
    );
    assert!(XMSS_SIGNATURE_SIZE == lean_xmss::SIG_SIZE);
    assert!(MAX_PROOFS <= lean_vm::MAX_RECURSIONS);
};

pub struct LeanVmTile {
    prover: Prover,
    reader: TCacheReader,
    producer: TProducer,
    aggregates: VecDeque<(u64, Aggregation)>,
    answers: Vec<LeanVmResp>,
}

enum Prover {
    /// No cores: every request is answered with `NoAnswer`.
    Off,
    /// The tile's core first. Starts in `try_init`, on the tile's thread.
    Cold(Vec<usize>),
    Warm,
}

impl Tile<SilverSpine> for LeanVmTile {
    /// Before any tile runs, so a request cannot precede the subscription.
    fn on_attach(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        adapter.subscribe_broadcast::<LeanVmReq>();
    }

    /// Announces the prover before the first loop, so a reader sees it ready
    /// before its first answer.
    fn try_init(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> bool {
        self.open_tcaches().expect("tcache wiring");
        if let Prover::Cold(cores) = &self.prover {
            start_prover(cores);
            self.prover = Prover::Warm;
            silver_log::info!("leanvm prover ready");
            adapter.set_ingestion_time(IngestionTime::now());
            adapter.produce(LeanVmReady);
        }
        true
    }

    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        self.producer.loop_start();
        self.intake(adapter);
        if let Some((request_id, aggregation)) = self.aggregates.pop_front() {
            let response = match aggregation.prove(request_id) {
                Ok((claims, proof)) => self.write_proven(request_id, &claims, &proof),
                Err(reason) => LeanVmResp::Refused { request_id, reason },
            };
            self.answers.push(response);
            adapter.mark_work();
        }
        self.publish(adapter);
    }
}

impl LeanVmTile {
    /// `cores`: the tile's own core first, which the caller pins the tile
    /// to, then the prover's other cores. Empty for no prover.
    pub fn new(cores: Vec<usize>, tcaches: TCacheTable, producer: TProducer) -> Self {
        Self {
            prover: if cores.is_empty() { Prover::Off } else { Prover::Cold(cores) },
            reader: TCacheReader::new(tcaches),
            producer,
            aggregates: VecDeque::with_capacity(MAX_QUEUED_AGGREGATES),
            answers: Vec::new(),
        }
    }

    pub fn open_tcaches(&mut self) -> Result<(), TCacheError> {
        self.reader.open(
            TCacheId::BeaconStateHandoff,
            "leanvm_beacon_state_handoff",
            TReadMode::Sliding,
        )
    }

    fn intake(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        // The previous pass drained the queue.
        self.reader.free();
        let Self { prover, reader, aggregates, answers, .. } = self;
        adapter.consume(|req: LeanVmReq, _| {
            let request_id = req.request_id;
            let result = match prover {
                Prover::Off | Prover::Cold(_) => Err(LeanVmResp::NoAnswer { request_id }),
                Prover::Warm if aggregates.len() == MAX_QUEUED_AGGREGATES => {
                    silver_log::warn!(request_id, "leanvm aggregate queue full");
                    Err(LeanVmResp::NoAnswer { request_id })
                }
                Prover::Warm => read_request(reader, req),
            };
            match result {
                Ok(aggregation) => aggregates.push_back((request_id, aggregation)),
                Err(response) => answers.push(response),
            }
        });
    }

    fn write_proven(
        &mut self,
        request_id: u64,
        claims: &AggregateClaims,
        proof: &[u8],
    ) -> LeanVmResp {
        let count = claims.lean_xmss.len();
        if claims.num_signature_claims() != count ||
            claims.da_commitment.is_some() ||
            count > MAX_PROOF_CLAIMS ||
            proof.len() > MAX_STARK_PROOF_SIZE
        {
            silver_log::error!(
                request_id,
                claims = count,
                proof = proof.len(),
                "leanvm output exceeds response format"
            );
            return LeanVmResp::Refused { request_id, reason: RefusalCode::ProvingFailed };
        }
        let len = ProofLen { claims: count as u32, proof: proof.len() as u32 };
        let body = self.producer.write_with(len.bytes(), |out| {
            let claims = claims.lean_xmss.iter().map(|(key, message)| {
                let mut claim = [0; size_of::<Claim>()];
                let (pubkey, target_message) = claim.split_at_mut(lean_xmss::PUB_KEY_SIZE);
                pubkey.copy_from_slice(&key.to_bytes());
                target_message.copy_from_slice(message);
                claim
            });
            ProofBody::write(out, claims, proof);
        });
        match body {
            Some(body) => {
                LeanVmResp::Proven { request_id, claims: len.claims, proof: len.proof, body }
            }
            None => {
                silver_log::error!(request_id, "leanvm tcache full; response dropped");
                LeanVmResp::NoAnswer { request_id }
            }
        }
    }

    fn publish(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        for resp in self.answers.drain(..) {
            adapter.produce(resp);
        }
    }
}

/// The cores the prover may use: one hardware thread per physical core this
/// process may run on, from CPU `first` on, in order. A core whose sibling
/// thread lies below `first` is left out: a tile or the logger already runs
/// there. The prover gains nothing from a second thread on a core.
pub fn physical_cores(first: usize) -> Vec<usize> {
    let mut allowed = flux::core_affinity::get_core_ids().unwrap_or_default();
    allowed.sort_unstable_by_key(|core| core.id);
    let mut seen = HashSet::new();
    allowed
        .into_iter()
        .map(|core| core.id)
        .filter(|&cpu| {
            let sibling = first_sibling(cpu);
            sibling >= first && seen.insert(sibling)
        })
        .collect()
}

/// The lowest CPU sharing `cpu`'s physical core, `cpu` itself when the
/// topology is unreadable.
fn first_sibling(cpu: usize) -> usize {
    let path = format!("/sys/devices/system/cpu/cpu{cpu}/topology/thread_siblings_list");
    let Ok(list) = std::fs::read_to_string(path) else { return cpu };
    // A list such as `1,17` or `0-1`: its first number is its lowest.
    let first = list.trim().split([',', '-']).next().and_then(|n| n.parse().ok());
    first.unwrap_or(cpu)
}

fn read_request(reader: &mut TCacheReader, req: LeanVmReq) -> Result<Aggregation, LeanVmResp> {
    let request_id = req.request_id;
    let refuse = |reason| LeanVmResp::Refused { request_id, reason };
    let malformed = |reason| {
        silver_log::warn!(request_id, ?reason, "leanvm request refused");
        refuse(RefusalCode::Malformed)
    };
    req.body_len().map_err(malformed)?;
    if req.signatures == 0 && req.proofs == 0 {
        silver_log::warn!(request_id, "leanvm request has no inputs");
        return Err(refuse(RefusalCode::InvalidInput));
    }
    let no_answer = LeanVmResp::NoAnswer { request_id };
    if !reader.is_open(req.body.id()) {
        silver_log::error!(request_id, "leanvm request outside the opened tcaches");
        return Err(no_answer);
    }
    let acquired = reader.acquire(req.body);
    let Ok((body, _)) = acquired.buffer() else {
        silver_log::warn!(request_id, "leanvm request lapped in the tcache");
        return Err(no_answer);
    };
    let aggregation = req
        .split(body)
        .map_err(malformed)
        .and_then(|body| Aggregation::decode(body, request_id).map_err(refuse));
    if acquired.revalidate().is_err() {
        silver_log::warn!(request_id, "leanvm request lapped in the tcache");
        return Err(no_answer);
    }
    aggregation
}

/// Starts leanVM's pool on `cores`, then pins the calling thread back to
/// `cores[0]` and warms the prover up.
///
/// The pool's workers inherit the calling thread's CPU set, so it spans
/// every prover core while they start.
#[timed]
fn start_prover(cores: &[usize]) {
    try_thread_boot(cores, None).expect("pin to the leanvm cores");
    lean_vm::setup(cores.len());
    try_thread_boot(&cores[..1], None).expect("pin to the leanvm tile core");
    warm_up();
    silver_log::info!(?cores, "leanvm prover started");
}

/// A fresh process's first proofs are slower, touching memory the allocator
/// then keeps. This pays for it before the first request: a discarded leaf
/// over one blob, the one input that needs no key, and a full recursion over
/// it, at the rate used in practice.
fn warm_up() {
    let blobs = lean_vm::lean_da::BlobMatrix::build(&[[0; lean_vm::lean_da::BLOB_SYMBOLS]])
        .expect("one blob");
    let leaf =
        lean_vm::aggregate(&[], vec![], vec![], Some(&blobs), OutputClaims::All, LOG_INV_RATE)
            .expect("the warm-up's leaf proves");
    let children = vec![leaf; lean_vm::MAX_RECURSIONS];
    lean_vm::aggregate(&children, vec![], vec![], None, OutputClaims::All, LOG_INV_RATE)
        .expect("the warm-up's recursion proves");
}

struct Aggregation {
    children: Vec<(AggregateClaims, AggregateProof)>,
    signatures: Vec<(LeanXmssPublicKey, lean_xmss::Message, LeanXmssSignature)>,
}

impl Aggregation {
    fn decode(body: RequestBody<'_>, request_id: u64) -> Result<Self, RefusalCode> {
        let children = body
            .children()
            .iter()
            .enumerate()
            .map(|(index, child)| {
                let proof = AggregateProof::from_bytes(child.proof()).ok_or_else(|| {
                    silver_log::warn!(
                        request_id,
                        child = index,
                        "leanvm child proof does not decode"
                    );
                    RefusalCode::InvalidChild
                })?;
                let lean_xmss = child.claims().iter().map(decode_claim).collect();
                Ok((AggregateClaims { lean_xmss, ..AggregateClaims::default() }, proof))
            })
            .collect::<Result<_, _>>()?;
        let signatures = body
            .signatures
            .iter()
            .map(|signed| {
                let (claim, signature) = signed.split_first_chunk().unwrap();
                let (key, message) = decode_claim(claim);
                (key, message, LeanXmssSignature::from_bytes(signature.as_array().unwrap()))
            })
            .collect();
        Ok(Self { children, signatures })
    }

    #[timed]
    fn prove(self, request_id: u64) -> Result<(AggregateClaims, Vec<u8>), RefusalCode> {
        let (children, signatures) = (self.children.len(), self.signatures.len());
        match lean_vm::aggregate(
            &self.children,
            self.signatures,
            vec![],
            None,
            OutputClaims::All,
            LOG_INV_RATE,
        ) {
            Ok((claims, proof)) => {
                silver_log::info!(
                    request_id,
                    children,
                    signatures,
                    rate = LOG_INV_RATE,
                    "leanvm proven"
                );
                Ok((claims, proof.to_bytes()))
            }
            Err(error) => {
                silver_log::warn!(
                    request_id, children, signatures, rate = LOG_INV_RATE, %error, "leanvm refused"
                );
                Err(refusal_code(error))
            }
        }
    }
}

fn decode_claim(claim: &Claim) -> (LeanXmssPublicKey, lean_xmss::Message) {
    let (key, message) = claim.split_first_chunk().unwrap();
    (LeanXmssPublicKey::from_bytes(key), *message.as_array().unwrap())
}

fn refusal_code(error: AggregateError) -> RefusalCode {
    match error {
        AggregateError::InvalidInput(_) => RefusalCode::InvalidInput,
        AggregateError::InvalidSignature => RefusalCode::InvalidSignature,
        AggregateError::InvalidChild => RefusalCode::InvalidChild,
        AggregateError::ProvingFailed => RefusalCode::ProvingFailed,
    }
}
