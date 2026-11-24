use flux::timing::Nanos;
use silver_common::{BlockSource, ColumnOrigin, PayloadValidationStatus, StfGate};

#[derive(Clone, Copy, Debug)]
pub enum Stage {
    /// A root's first `BlockReceived`, at its ingestion.
    Received {
        source: BlockSource,
    },
    ColumnRecv {
        index: u64,
        origin: ColumnOrigin,
    },
    /// The same sidecar past validation; the gap from `ColumnRecv` is the
    /// columns tile's queue delay.
    ColumnValidated {
        index: u64,
        origin: ColumnOrigin,
    },
    /// `NewPayload` publish: CL validated, dispatched to the EL
    ElSent {
        source: BlockSource,
    },
    ElVerdict {
        verdict: PayloadValidationStatus,
    },
    DaAvailable,
    /// Every column this node custodies is held: the 64 → 128 tail past the
    /// gate, a duty of the node rather than a wait of the block.
    CustodyDone,
    /// CL validation passed; the transition starts.
    Validated,
    /// Post-state committed: publish of the announcement that ran the
    /// transition. Precedes `Attestable` when `gate` held the import.
    StfDone {
        gate: StfGate,
    },
    /// In fork choice with the new head published: publish of the
    /// root's first `BlockReceived { stage: Applied }`, ahead of the FCU.
    Attestable,
    /// The transition, leanVM or the EL rejected the block.
    Rejected,
    /// A local validator's vote for the block passed gossip validation. The
    /// event's slot is the vote's, which is later than the block's when the
    /// vote's own slot had no block.
    LocalAttestation,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Self::Received { .. } => "received",
            Self::ColumnValidated { .. } => "column_validated",
            Self::ColumnRecv { .. } => "column_recv",
            Self::ElSent { .. } => "el_sent",
            Self::ElVerdict { .. } => "el_verdict",
            Self::DaAvailable => "da_available",
            Self::CustodyDone => "custody_done",
            Self::Validated => "validated",
            Self::StfDone { .. } => "stf_done",
            Self::Attestable => "attestable",
            Self::Rejected => "rejected",
            Self::LocalAttestation => "local_attestation",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StageEvent {
    pub stage: Stage,
    /// Wall clock of the event (unix epoch).
    pub ts: Nanos,
    pub block_root: [u8; 32],
    /// `None` when the message carries no slot and the root was first seen
    /// before the reader attached.
    pub slot: Option<u64>,
}
