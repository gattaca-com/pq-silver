use crate::{
    ssz_hash_gloas::{ExecutionRequestsView, RequestCountOutOfBounds},
    ssz_view::{
        BEACON_BLOCK_BODY_FIXED, BEACON_BLOCK_BODY_PQ_FIXED, BeaconBlockBodyFuluView,
        BeaconBlockBodyPqView, DEPOSIT_SIZE, ETH1_DATA_SIZE, EXECUTION_PAYLOAD_FIXED,
        EXECUTION_PAYLOAD_HEADER_FIXED, MAX_ATTESTATIONS_ELECTRA, MAX_ATTESTER_SLASHINGS_ELECTRA,
        MAX_BLS_TO_EXECUTION_CHANGES, MAX_PAYLOAD_ATTESTATIONS, MAX_PROPOSER_SLASHINGS,
        MAX_VOLUNTARY_EXITS, PAYLOAD_ATTESTATION_SIZE, PROPOSER_SLASHING_SIZE,
        SIGNED_BLS_CHANGE_SIZE, SIGNED_VOLUNTARY_EXIT_SIZE, variable_list_len,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    ProposerSlashings,
    AttesterSlashings,
    Attestations,
    Deposits,
    VoluntaryExits,
    BlsToExecutionChanges,
    PayloadAttestations,
}

impl OperationKind {
    pub(crate) fn check_count(self, count: usize, max: usize) -> Result<(), BlockBodyError> {
        if count > max {
            Err(BlockBodyError::OperationCountOutOfBounds { op: self, count, max })
        } else {
            Ok(())
        }
    }
}

impl core::fmt::Display for OperationKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Self::ProposerSlashings => "proposer_slashings",
            Self::AttesterSlashings => "attester_slashings",
            Self::Attestations => "attestations",
            Self::Deposits => "deposits",
            Self::VoluntaryExits => "voluntary_exits",
            Self::BlsToExecutionChanges => "bls_to_execution_changes",
            Self::PayloadAttestations => "payload_attestations",
        };
        f.write_str(s)
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum BlockBodyError {
    #[error("block body too short: len={len} min={min}")]
    BodyTooShort { len: usize, min: usize },
    #[error("execution payload too short: len={len} min={min}")]
    PayloadTooShort { len: usize, min: usize },
    #[error("execution payload header too short: len={len} min={min}")]
    PayloadHeaderTooShort { len: usize, min: usize },
    #[error("{op} count {count} exceeds max {max}")]
    OperationCountOutOfBounds { op: OperationKind, count: usize, max: usize },
    #[error("parent {kind} request count {count} exceeds max {max}")]
    RequestCountOutOfBounds { kind: &'static str, count: usize, max: usize },
    #[error(
        "body offset malformed: {field} off={off} body_len={body_len} \
         (next_field_off={next_off:?})"
    )]
    BodyOffsetOutOfRange {
        field: &'static str,
        off: usize,
        next_off: Option<usize>,
        body_len: usize,
    },
    #[error("{fork:?} body is not canonical SSZ (len {len})")]
    NotCanonical { fork: BodyFork, len: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BodyFork {
    Fulu,
    FuluBlinded,
    Gloas,
    Pq,
}

/// Where a fork's body keeps its variable fields: the offset positions in the
/// fixed part, in serialization order, and the fields' names. Each field
/// index past `deposits` is `None` where the fork has no such field.
struct BodyLayout {
    fixed_len: usize,
    offsets: &'static [usize],
    names: &'static [&'static str],
    voluntary_exits: Option<usize>,
    bls_changes: Option<usize>,
    signed_bid: Option<usize>,
    payload_attestations: Option<usize>,
    parent_execution_requests: Option<usize>,
    proof: Option<usize>,
}

const MAX_VARIABLE_FIELDS: usize = 9;

impl BodyFork {
    fn layout(self) -> &'static BodyLayout {
        const fn fulu(execution: &'static str) -> [&'static str; 9] {
            [
                "proposer_slashings",
                "attester_slashings",
                "attestations",
                "deposits",
                "voluntary_exits",
                execution,
                "bls_to_execution_changes",
                "blob_kzg_commitments",
                "execution_requests",
            ]
        }
        const FULU: BodyLayout = BodyLayout {
            fixed_len: BEACON_BLOCK_BODY_FIXED,
            offsets: &BeaconBlockBodyFuluView::VARIABLE_OFFSETS,
            names: &fulu("execution_payload"),
            voluntary_exits: Some(4),
            bls_changes: Some(6),
            signed_bid: None,
            payload_attestations: None,
            parent_execution_requests: None,
            proof: None,
        };
        const FULU_BLINDED: BodyLayout =
            BodyLayout { names: &fulu("execution_payload_header"), ..FULU };
        // Gloas keeps Fulu's fixed part, so its offsets sit at the same positions.
        const GLOAS: BodyLayout = BodyLayout {
            names: &[
                "proposer_slashings",
                "attester_slashings",
                "attestations",
                "deposits",
                "voluntary_exits",
                "bls_to_execution_changes",
                "signed_execution_payload_bid",
                "payload_attestations",
                "parent_execution_requests",
            ],
            bls_changes: Some(5),
            signed_bid: Some(6),
            payload_attestations: Some(7),
            parent_execution_requests: Some(8),
            ..FULU
        };
        const PQ: BodyLayout = BodyLayout {
            fixed_len: BEACON_BLOCK_BODY_PQ_FIXED,
            offsets: &BeaconBlockBodyPqView::VARIABLE_OFFSETS,
            names: &[
                "proposer_slashings",
                "attester_slashings",
                "attestations",
                "deposits",
                "signed_execution_payload_bid",
                "parent_execution_requests",
                "proof",
            ],
            voluntary_exits: None,
            bls_changes: None,
            signed_bid: Some(4),
            payload_attestations: None,
            parent_execution_requests: Some(5),
            proof: Some(6),
        };
        match self {
            Self::Fulu => &FULU,
            Self::FuluBlinded => &FULU_BLINDED,
            Self::Gloas => &GLOAS,
            Self::Pq => &PQ,
        }
    }
}

impl From<RequestCountOutOfBounds> for BlockBodyError {
    fn from(e: RequestCountOutOfBounds) -> Self {
        Self::RequestCountOutOfBounds { kind: e.kind, count: e.count, max: e.max }
    }
}

/// Payload bytes with the fixed prefix present, so every `ExecutionPayloadView`
/// accessor is in bounds.
#[derive(Clone, Copy)]
pub struct Payload<'a>(&'a [u8]);

impl<'a> Payload<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, BlockBodyError> {
        if bytes.len() < EXECUTION_PAYLOAD_FIXED {
            return Err(BlockBodyError::PayloadTooShort {
                len: bytes.len(),
                min: EXECUTION_PAYLOAD_FIXED,
            });
        }
        Ok(Self(bytes))
    }

    #[inline]
    pub fn bytes(self) -> &'a [u8] {
        self.0
    }
}

/// A body's fixed part and variable fields, which need not share one buffer:
/// a proposer assembles its body from the pieces it holds.
#[derive(Clone, Copy)]
pub struct BodyOffsets<'a> {
    fork: BodyFork,
    fixed: &'a [u8],
    /// `None` for a field whose offsets do not bound a slice of the body, or
    /// past the fork's last field.
    fields: [Option<&'a [u8]>; MAX_VARIABLE_FIELDS],
    len: usize,
    serialized: Option<&'a [u8]>,
}

impl<'a> BodyOffsets<'a> {
    pub fn new(body: &'a [u8], fork: BodyFork) -> Result<Self, BlockBodyError> {
        let layout = fork.layout();
        if body.len() < layout.fixed_len {
            return Err(BlockBodyError::BodyTooShort { len: body.len(), min: layout.fixed_len });
        }
        let fixed = &body[..layout.fixed_len];
        let count = layout.offsets.len();
        let fields = std::array::from_fn(|i| {
            if i >= count {
                return None;
            }
            let start = read_offset(fixed, layout.offsets[i]);
            let end =
                if i + 1 < count { read_offset(fixed, layout.offsets[i + 1]) } else { body.len() };
            (start <= end && end <= body.len()).then(|| &body[start..end])
        });
        let offsets = Self { fork, fixed, fields, len: body.len(), serialized: Some(body) };
        offsets.check_execution_field()?;
        Ok(offsets)
    }

    /// A Fulu body from its fixed part and each variable field in
    /// serialization order.
    pub(crate) fn from_parts(
        fixed: &'a [u8],
        fields: [&'a [u8]; 9],
        fork: BodyFork,
    ) -> Result<Self, BlockBodyError> {
        assert_eq!(fixed.len(), BEACON_BLOCK_BODY_FIXED, "the fixed part is exactly fixed-size");
        assert!(
            matches!(fork, BodyFork::Fulu | BodyFork::FuluBlinded),
            "a post-Gloas body is parsed whole"
        );
        let len = BEACON_BLOCK_BODY_FIXED + fields.iter().map(|field| field.len()).sum::<usize>();
        let offsets = Self { fork, fixed, fields: fields.map(Some), len, serialized: None };
        offsets.check_execution_field()?;
        Ok(offsets)
    }

    /// Bounds every fixed-offset accessor of field 5's view.
    fn check_execution_field(&self) -> Result<(), BlockBodyError> {
        match self.fork {
            BodyFork::Fulu => Payload::new(self.execution_field()).map(|_| ()),
            BodyFork::FuluBlinded => {
                let len = self.execution_field().len();
                if len < EXECUTION_PAYLOAD_HEADER_FIXED {
                    return Err(BlockBodyError::PayloadHeaderTooShort {
                        len,
                        min: EXECUTION_PAYLOAD_HEADER_FIXED,
                    });
                }
                Ok(())
            }
            BodyFork::Gloas | BodyFork::Pq => Ok(()),
        }
    }

    pub fn validated(body: &'a [u8], fork: BodyFork) -> Result<Self, BlockBodyError> {
        let offsets = Self::new(body, fork)?;
        offsets.validate()?;
        Ok(offsets)
    }

    #[inline]
    pub fn fork(&self) -> BodyFork {
        self.fork
    }

    /// `randao_reveal`, `eth1_data`, `graffiti`, the offsets and, before PQ,
    /// `sync_aggregate`: every accessor of the fixed layout reads it.
    #[inline]
    pub fn fixed(&self) -> &'a [u8] {
        self.fixed
    }

    #[inline]
    pub fn eth1_data(&self) -> &'a [u8; ETH1_DATA_SIZE] {
        match self.fork {
            BodyFork::Fulu | BodyFork::FuluBlinded | BodyFork::Gloas => {
                BeaconBlockBodyFuluView::eth1_data(self.fixed)
            }
            BodyFork::Pq => BeaconBlockBodyPqView::eth1_data(self.fixed),
        }
    }

    /// The body as one buffer, when it was parsed from one.
    #[inline]
    pub fn serialized(&self) -> Option<&'a [u8]> {
        self.serialized
    }

    #[inline]
    pub fn proposer_slashings(&self) -> Option<&'a [u8]> {
        self.fields[0]
    }
    #[inline]
    pub fn attester_slashings(&self) -> Option<&'a [u8]> {
        self.fields[1]
    }
    #[inline]
    pub fn attestations(&self) -> Option<&'a [u8]> {
        self.fields[2]
    }
    #[inline]
    pub fn deposits(&self) -> Option<&'a [u8]> {
        self.fields[3]
    }
    #[inline]
    pub fn voluntary_exits(&self) -> Option<&'a [u8]> {
        self.field(self.fork.layout().voluntary_exits)
    }
    #[inline]
    pub fn bls_changes(&self) -> Option<&'a [u8]> {
        self.field(self.fork.layout().bls_changes)
    }
    #[inline]
    pub fn sync_aggregate(&self) -> Option<&'a [u8]> {
        match self.fork {
            BodyFork::Fulu | BodyFork::FuluBlinded | BodyFork::Gloas => {
                Some(&BeaconBlockBodyFuluView::sync_aggregate(self.fixed)[..])
            }
            BodyFork::Pq => None,
        }
    }

    #[inline]
    fn field(&self, index: Option<usize>) -> Option<&'a [u8]> {
        self.fields[index?]
    }

    #[inline]
    pub fn payload(&self) -> Payload<'a> {
        debug_assert_eq!(self.fork, BodyFork::Fulu);
        Payload(self.execution_field())
    }

    #[inline]
    pub fn payload_header(&self) -> &'a [u8] {
        debug_assert_eq!(self.fork, BodyFork::FuluBlinded);
        self.execution_field()
    }

    fn execution_field(&self) -> &'a [u8] {
        debug_assert!(matches!(self.fork, BodyFork::Fulu | BodyFork::FuluBlinded));
        self.fields[5].unwrap_or(&[])
    }

    #[inline]
    pub fn blob_commitments_fulu(&self) -> &'a [u8] {
        debug_assert!(matches!(self.fork, BodyFork::Fulu | BodyFork::FuluBlinded));
        self.fields[7].unwrap_or(&[])
    }

    #[inline]
    pub fn execution_requests(&self) -> &'a [u8] {
        debug_assert!(matches!(self.fork, BodyFork::Fulu | BodyFork::FuluBlinded));
        self.fields[8].unwrap_or(&[])
    }

    #[inline]
    pub fn signed_bid(&self) -> Option<&'a [u8]> {
        self.field(self.fork.layout().signed_bid)
    }
    #[inline]
    pub fn payload_attestations(&self) -> Option<&'a [u8]> {
        self.field(self.fork.layout().payload_attestations)
    }

    #[inline]
    pub fn parent_execution_requests(&self) -> &'a [u8] {
        self.field(self.fork.layout().parent_execution_requests).unwrap_or(&[])
    }

    #[inline]
    pub fn proof(&self) -> &'a [u8] {
        self.field(self.fork.layout().proof).unwrap_or(&[])
    }

    /// Offset-table (in-bounds + monotone) and operation-count validation. The
    /// structural and shared-cap checks run for every pre-PQ fork; Gloas
    /// additionally caps payload attestations. A PQ body is checked whole,
    /// down to its operations' layouts and the proof's size limit.
    pub fn validate(&self) -> Result<(), BlockBodyError> {
        if self.fork == BodyFork::Pq {
            let body = self.serialized.expect("a PQ body is parsed whole");
            if !BeaconBlockBodyPqView::check_canonical(body) {
                return Err(BlockBodyError::NotCanonical { fork: self.fork, len: body.len() });
            }
            return BeaconBlockBodyPqView::check_operation_limits(body);
        }

        let body_len = self.len;
        let layout = self.fork.layout();
        let offset = |i: usize| read_offset(self.fixed, layout.offsets[i]);
        for (i, &field) in layout.names.iter().enumerate() {
            let off = offset(i);
            let next_off = (i + 1 < layout.offsets.len()).then(|| offset(i + 1));
            if off > body_len || next_off.is_some_and(|n| n < off) {
                return Err(BlockBodyError::BodyOffsetOutOfRange { field, off, next_off, body_len });
            }
        }

        let fixed_count = |s: Option<&[u8]>, elem: usize| s.map_or(0, |s| s.len() / elem);
        let var_count = |s: Option<&[u8]>| s.map_or(0, variable_list_len);

        OperationKind::ProposerSlashings.check_count(
            fixed_count(self.proposer_slashings(), PROPOSER_SLASHING_SIZE),
            MAX_PROPOSER_SLASHINGS,
        )?;
        OperationKind::AttesterSlashings
            .check_count(var_count(self.attester_slashings()), MAX_ATTESTER_SLASHINGS_ELECTRA)?;
        OperationKind::Attestations
            .check_count(var_count(self.attestations()), MAX_ATTESTATIONS_ELECTRA)?;
        OperationKind::VoluntaryExits.check_count(
            fixed_count(self.voluntary_exits(), SIGNED_VOLUNTARY_EXIT_SIZE),
            MAX_VOLUNTARY_EXITS,
        )?;
        OperationKind::BlsToExecutionChanges.check_count(
            fixed_count(self.bls_changes(), SIGNED_BLS_CHANGE_SIZE),
            MAX_BLS_TO_EXECUTION_CHANGES,
        )?;

        // Fulu removed the eth1 bridge deposit; the field must be empty.
        if self.deposits().is_some_and(|d| !d.is_empty()) {
            return Err(BlockBodyError::OperationCountOutOfBounds {
                op: OperationKind::Deposits,
                count: fixed_count(self.deposits(), DEPOSIT_SIZE).max(1),
                max: 0,
            });
        }

        if self.fork == BodyFork::Gloas {
            OperationKind::PayloadAttestations.check_count(
                fixed_count(self.payload_attestations(), PAYLOAD_ATTESTATION_SIZE),
                MAX_PAYLOAD_ATTESTATIONS,
            )?;
            ExecutionRequestsView::check_counts(self.parent_execution_requests())?;
        }

        Ok(())
    }
}

fn read_offset(fixed: &[u8], at: usize) -> usize {
    u32::from_le_bytes(fixed[at..at + 4].try_into().expect("4 bytes")) as usize
}
