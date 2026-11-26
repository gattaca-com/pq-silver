use std::{
    convert::Infallible,
    io::{self, Write},
    ops::Range,
};

use blst::{blst_p1_affine, min_pk::PublicKey};
use flux_profiler::timed;
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use silver_crypto_simd::bls::{G1Point, uncompress_in_g1};
use silver_state_memory::RetainedVec;

use super::scheme::{SchemeColumn, SchemeKey};
use crate::{
    Withdrawals,
    merkle::{merkleize_each, uint64_chunk},
    pq::{KeyScheme, xmss_pubkey, xmss_pubkey_padded},
    slot_state::{EpochBalances, EpochBalancesRow},
    types::{B256, BLSPubkey, Epoch, FAR_FUTURE_EPOCH, validator_capacity},
};

pub type PubkeyIndex = FxHashMap<BLSPubkey, u32>;

/// Initial values for one validator passed to
/// [`FinalizedValidators::with_validators`]. Test-fixture input (reaches other
/// crates' tests through `for_test`), hidden from the public API.
#[doc(hidden)]
pub struct ValSeed {
    pub pubkey: BLSPubkey,
    pub withdrawal_credentials: Withdrawals,
    pub effective_balance: u64,
    pub balance: u64,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
}

impl Default for ValSeed {
    fn default() -> Self {
        Self {
            pubkey: [0u8; 48],
            withdrawal_credentials: Withdrawals::default(),
            effective_balance: 0,
            balance: 0,
            activation_epoch: FAR_FUTURE_EPOCH,
            exit_epoch: FAR_FUTURE_EPOCH,
        }
    }
}

/// Full per-validator field set, used only to construct or grow the finalized
/// base (SSZ decode, genesis seeds). The fork delta's [`AppendedValidator`] is
/// leaner — its mutable fields are always spec-defaults at append time.
pub(super) struct ValidatorInit {
    pub pubkey: BLSPubkey,
    pub scheme_key: SchemeKey,
    pub credentials: Withdrawals,
    pub effective_balance: u64,
    pub slashed: bool,
    pub activation_eligibility_epoch: Epoch,
    pub activation_epoch: Epoch,
    pub exit_epoch: Epoch,
    pub withdrawable_epoch: Epoch,
}

/// Byte offset of each SSZ `Validator` field after the key fields, packed
/// contiguously: `withdrawal_credentials[32] | effective_balance:u64 |
/// slashed:bool | 4 × epoch:u64`. The key fields are `pubkey[48]` before
/// PQ, and `pubkey[32] | vrf_root[32]` in PQ.
mod offset {
    pub const CREDENTIALS: usize = 0;
    pub const EFFECTIVE_BALANCE: usize = 32;
    pub const SLASHED: usize = 40;
    pub const ACTIVATION_ELIGIBILITY_EPOCH: usize = 41;
    pub const ACTIVATION_EPOCH: usize = 49;
    pub const EXIT_EPOCH: usize = 57;
    pub const WITHDRAWABLE_EPOCH: usize = 65;
    pub const END: usize = 73;
}

const VALIDATOR_SSZ_SIZE: usize = 48 + offset::END;
pub(crate) const VALIDATOR_PQ_SSZ_SIZE: usize = 32 + 32 + offset::END;

#[derive(Debug, thiserror::Error)]
pub enum ValidatorsDecodeError {
    #[error("validators bytes {len} not a multiple of {size}")]
    LenNotMultiple { len: usize, size: usize },
    #[error("validator {idx} pubkey failed BLS decompression")]
    InvalidPubkey { idx: usize },
    #[error("pubkey sidecar count {sidecar} != validator count {validators}")]
    PubkeyCountMismatch { sidecar: usize, validators: usize },
    #[error("validator {idx} sidecar pubkey does not match the canonical compressed pubkey")]
    PubkeyMismatch { idx: usize },
    #[error("validator count {n} exceeds the u32 index space")]
    TooMany { n: usize },
}

fn record_count(val_bytes: &[u8], size: usize) -> Result<usize, ValidatorsDecodeError> {
    if !val_bytes.len().is_multiple_of(size) {
        return Err(ValidatorsDecodeError::LenNotMultiple { len: val_bytes.len(), size });
    }
    let n = val_bytes.len() / size;
    if u32::try_from(n).is_err() {
        return Err(ValidatorsDecodeError::TooMany { n });
    }
    Ok(n)
}

impl ValidatorInit {
    fn from_shared_fields(pubkey: BLSPubkey, scheme_key: SchemeKey, shared: &[u8]) -> Self {
        Self {
            pubkey,
            scheme_key,
            credentials: Withdrawals(
                shared[offset::CREDENTIALS..offset::EFFECTIVE_BALANCE].try_into().unwrap(),
            ),
            effective_balance: u64_at(shared, offset::EFFECTIVE_BALANCE),
            slashed: shared[offset::SLASHED] != 0,
            activation_eligibility_epoch: u64_at(shared, offset::ACTIVATION_ELIGIBILITY_EPOCH),
            activation_epoch: u64_at(shared, offset::ACTIVATION_EPOCH),
            exit_epoch: u64_at(shared, offset::EXIT_EPOCH),
            withdrawable_epoch: u64_at(shared, offset::WITHDRAWABLE_EPOCH),
        }
    }
}

#[inline]
fn u64_at(s: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(s[off..off + 8].try_into().unwrap())
}

/// A multiple of the decoder's eight lanes, so only the final batch can have
/// a scalar tail.
pub(super) const DECODE_CHUNK: usize = 1024;

/// Validates record pubkeys in batches as `build` reads them in order,
/// avoiding a temporary key buffer for the whole registry.
struct RecordKeys<'a> {
    val_bytes: &'a [u8],
    start: usize,
    compressed: Vec<BLSPubkey>,
    decoded: Vec<Option<G1Point>>,
}

impl<'a> RecordKeys<'a> {
    fn new(val_bytes: &'a [u8]) -> Self {
        Self {
            val_bytes,
            start: 0,
            compressed: Vec::with_capacity(DECODE_CHUNK),
            decoded: vec![None; DECODE_CHUNK],
        }
    }

    fn key(&mut self, idx: usize) -> Result<PublicKey, ValidatorsDecodeError> {
        debug_assert!(idx >= self.start, "records are read in order");
        if idx >= self.start + self.compressed.len() {
            self.decode_batch(idx);
        }
        // Decoding checks G1 membership; `KeyValidate` also rejects infinity,
        // represented by blst as the all-zero point.
        match self.decoded[idx - self.start] {
            Some(point) if *point.as_blst() != blst_p1_affine::default() => {
                Ok(PublicKey::from(point.into_blst()))
            }
            _ => Err(ValidatorsDecodeError::InvalidPubkey { idx }),
        }
    }

    fn decode_batch(&mut self, start: usize) {
        let records = &self.val_bytes[start * VALIDATOR_SSZ_SIZE..];
        let records = &records[..records.len().min(DECODE_CHUNK * VALIDATOR_SSZ_SIZE)];
        self.compressed.clear();
        self.compressed.extend(
            records
                .as_chunks::<VALIDATOR_SSZ_SIZE>()
                .0
                .iter()
                .map(|v| BLSPubkey::try_from(&v[..48]).unwrap()),
        );
        self.start = start;
        uncompress_in_g1(&self.compressed, &mut self.decoded[..self.compressed.len()]);
    }
}

#[inline]
pub(super) fn slashed_bit(slashed: &[u8], i: usize) -> bool {
    slashed[i / 8] & (1u8 << (i % 8)) != 0
}

#[inline]
fn put(buf: &mut [u8], off: usize, src: &[u8]) {
    buf[off..off + src.len()].copy_from_slice(src);
}

pub struct FinalizedValidators {
    /// The 48-byte form of each pubkey, whichever the scheme.
    pub(super) val_pubkey: RetainedVec<BLSPubkey>,
    pub(super) scheme_keys: SchemeColumn,
    pub(super) val_withdrawal_credentials: RetainedVec<Withdrawals>,
    pub(super) effective_balance: RetainedVec<u64>,
    /// Bitset: validator `i` is slashed iff
    /// `slashed[i / 8] & (1 << (i % 8)) != 0`. Length = `capacity / 8`.
    pub(super) slashed: RetainedVec<u8>,
    pub(super) activation_eligibility_epoch: RetainedVec<Epoch>,
    pub(super) activation_epoch: RetainedVec<Epoch>,
    pub(super) exit_epoch: RetainedVec<Epoch>,
    pub(super) withdrawable_epoch: RetainedVec<Epoch>,
    pub(super) index: RwLock<PubkeyIndex>,
}

impl FinalizedValidators {
    fn build<E>(
        scheme: KeyScheme,
        capacity: usize,
        n: usize,
        mut field_at: impl FnMut(usize) -> Result<ValidatorInit, E>,
    ) -> Result<Self, E> {
        debug_assert!(n <= capacity);
        let mut this = Self {
            val_pubkey: RetainedVec::with_capacity(capacity),
            scheme_keys: SchemeColumn::with_capacity(scheme, capacity),
            val_withdrawal_credentials: RetainedVec::with_capacity(capacity),
            effective_balance: RetainedVec::with_capacity(capacity),
            slashed: RetainedVec::with_capacity(capacity.div_ceil(8)),
            activation_eligibility_epoch: RetainedVec::with_capacity(capacity),
            activation_epoch: RetainedVec::with_capacity(capacity),
            exit_epoch: RetainedVec::with_capacity(capacity),
            withdrawable_epoch: RetainedVec::with_capacity(capacity),
            index: RwLock::new(PubkeyIndex::with_capacity_and_hasher(n, Default::default())),
        };
        this.extend_to(n);

        let index = this.index.get_mut();
        for i in 0..n {
            let f = field_at(i)?;
            this.val_pubkey[i] = f.pubkey;
            this.scheme_keys.set(i, f.scheme_key);
            this.val_withdrawal_credentials[i] = f.credentials;
            this.effective_balance[i] = f.effective_balance;
            if f.slashed {
                this.slashed[i / 8] |= 1u8 << (i % 8);
            }
            this.activation_eligibility_epoch[i] = f.activation_eligibility_epoch;
            this.activation_epoch[i] = f.activation_epoch;
            this.exit_epoch[i] = f.exit_epoch;
            this.withdrawable_epoch[i] = f.withdrawable_epoch;
            index.insert(f.pubkey, i as u32);
        }
        Ok(this)
    }

    /// Appends spec-default validators up to `count`. Each column's length is
    /// the validator count, so a racing reader's slice never covers slots its
    /// block has not filled.
    pub(super) fn extend_to(&mut self, count: usize) {
        if count > self.capacity() {
            self.grow(count);
        }
        self.val_pubkey.resize(count, [0u8; 48]);
        self.scheme_keys.resize(count);
        self.val_withdrawal_credentials.resize(count, Withdrawals::default());
        self.effective_balance.resize(count, 0);
        self.slashed.resize(count.div_ceil(8), 0);
        self.activation_eligibility_epoch.resize(count, FAR_FUTURE_EPOCH);
        self.activation_epoch.resize(count, FAR_FUTURE_EPOCH);
        self.exit_epoch.resize(count, FAR_FUTURE_EPOCH);
        self.withdrawable_epoch.resize(count, FAR_FUTURE_EPOCH);
    }

    /// Deposits outgrow the boot-time headroom on a long-running node.
    #[cold]
    fn grow(&mut self, needed: usize) {
        let capacity = validator_capacity(needed);
        self.val_pubkey.grow_to(capacity);
        self.scheme_keys.grow_to(capacity);
        self.val_withdrawal_credentials.grow_to(capacity);
        self.effective_balance.grow_to(capacity);
        self.slashed.grow_to(capacity.div_ceil(8));
        self.activation_eligibility_epoch.grow_to(capacity);
        self.activation_epoch.grow_to(capacity);
        self.exit_epoch.grow_to(capacity);
        self.withdrawable_epoch.grow_to(capacity);
        silver_log::info!(
            validators = self.validator_count(),
            capacity,
            "finalized validator columns grew"
        );
    }
}

impl FinalizedValidators {
    /// Decode the SSZ `validators` byte range (layout per [`offset`]); capacity
    /// is derived from the count, and `try_new(&[], None)` is the empty base.
    /// With `Some(decompressed)`, each sidecar key is bound to its record's
    /// canonical compressed pubkey; with `None`, valid pubkeys are decompressed
    /// from the records and invalid are rejected. The sidecar is optional.
    #[timed]
    pub fn try_new(
        val_bytes: &[u8],
        decompressed: Option<&[PublicKey]>,
    ) -> Result<Self, ValidatorsDecodeError> {
        let n = record_count(val_bytes, VALIDATOR_SSZ_SIZE)?;
        if let Some(d) = decompressed {
            if d.len() != n {
                return Err(ValidatorsDecodeError::PubkeyCountMismatch {
                    sidecar: d.len(),
                    validators: n,
                });
            }
        }

        let mut record_keys = RecordKeys::new(val_bytes);
        Self::build(KeyScheme::Bls, validator_capacity(n), n, |i| {
            let (pubkey, shared) = val_bytes[i * VALIDATOR_SSZ_SIZE..].split_at(48);
            let pubkey: BLSPubkey = pubkey.try_into().unwrap();
            let pubkey_decompressed = match decompressed {
                Some(d) if d[i].compress() != pubkey => {
                    return Err(ValidatorsDecodeError::PubkeyMismatch { idx: i });
                }
                Some(d) => d[i],
                None => record_keys.key(i)?,
            };
            Ok(ValidatorInit::from_shared_fields(
                pubkey,
                SchemeKey::Bls(pubkey_decompressed),
                shared,
            ))
        })
    }

    /// Decode the PQ SSZ `validators` byte range. XMSS keys need no
    /// validation: any 32 bytes are a key.
    #[timed]
    pub fn try_new_xmss(val_bytes: &[u8]) -> Result<Self, ValidatorsDecodeError> {
        let n = record_count(val_bytes, VALIDATOR_PQ_SSZ_SIZE)?;
        Self::build(KeyScheme::Xmss, validator_capacity(n), n, |i| {
            let v = &val_bytes[i * VALIDATOR_PQ_SSZ_SIZE..];
            Ok::<_, Infallible>(ValidatorInit::from_shared_fields(
                xmss_pubkey_padded(v[..32].try_into().unwrap()),
                SchemeKey::Xmss { vrf_root: v[32..64].try_into().unwrap() },
                &v[64..],
            ))
        })
        .map_err(|e| match e {})
    }

    #[inline]
    /// SSZ-encode validators `[start, end)` — the checkpoint persist's
    /// section body, called in bounded slices.
    pub(crate) fn write_ssz_range<W: Write>(
        &self,
        start: usize,
        end: usize,
        w: &mut W,
    ) -> io::Result<()> {
        let mut buf = [0u8; VALIDATOR_PQ_SSZ_SIZE];
        let record = &mut buf[..self.ssz_record_size()];
        for i in start..end {
            let (keys, shared) = record.split_at_mut(record.len() - offset::END);
            match &self.scheme_keys {
                SchemeColumn::Bls(_) => keys.copy_from_slice(&self.val_pubkey[i]),
                SchemeColumn::Xmss(vrf_roots) => {
                    keys[..32].copy_from_slice(xmss_pubkey(&self.val_pubkey[i]));
                    keys[32..].copy_from_slice(&vrf_roots[i]);
                }
            }
            self.put_shared_fields(i, shared);
            w.write_all(record)?;
        }
        Ok(())
    }

    fn put_shared_fields(&self, i: usize, shared: &mut [u8]) {
        put(shared, offset::CREDENTIALS, &self.val_withdrawal_credentials[i].0);
        put(shared, offset::EFFECTIVE_BALANCE, &self.effective_balance[i].to_le_bytes());
        shared[offset::SLASHED] = self.is_slashed(i) as u8;
        let elig = self.activation_eligibility_epoch[i].to_le_bytes();
        put(shared, offset::ACTIVATION_ELIGIBILITY_EPOCH, &elig);
        put(shared, offset::ACTIVATION_EPOCH, &self.activation_epoch[i].to_le_bytes());
        put(shared, offset::EXIT_EPOCH, &self.exit_epoch[i].to_le_bytes());
        put(shared, offset::WITHDRAWABLE_EPOCH, &self.withdrawable_epoch[i].to_le_bytes());
    }

    pub(crate) fn ssz_record_size(&self) -> usize {
        match self.scheme() {
            KeyScheme::Bls => VALIDATOR_SSZ_SIZE,
            KeyScheme::Xmss => VALIDATOR_PQ_SSZ_SIZE,
        }
    }

    #[inline]
    pub fn scheme(&self) -> KeyScheme {
        self.scheme_keys.scheme()
    }

    /// Write the decompressed (96-B serialized) pubkeys `[start, end)` — the
    /// checkpoint sidecar's body, called in bounded slices.
    pub(crate) fn write_pubkeys_range<W: Write>(
        &self,
        start: usize,
        end: usize,
        w: &mut W,
    ) -> io::Result<()> {
        assert!(start >= end || self.scheme() == KeyScheme::Bls, "only BLS keys are decompressed");
        for i in start..end {
            w.write_all(&self.scheme_keys.bls(i).serialize())?;
        }
        Ok(())
    }

    pub fn validator_count(&self) -> usize {
        self.val_pubkey.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.val_pubkey.capacity()
    }

    /// `slashed` is a bitset (validator `i` at bit `i % 8` of byte `i / 8`), so
    /// it keeps a reader rather than callers open-coding the mask. Every other
    /// column is read directly through its `pub(super)` field.
    #[inline]
    pub(super) fn is_slashed(&self, i: usize) -> bool {
        slashed_bit(&self.slashed, i)
    }

    pub(crate) fn effective_balances(&self) -> impl Iterator<Item = u64> + '_ {
        self.effective_balance.iter().copied()
    }

    pub(crate) fn sweep_epoch_balances(
        &self,
        prev_participation: &[u8],
        curr_participation: &[u8],
        current_epoch: Epoch,
    ) -> EpochBalances {
        let n = self.validator_count();
        debug_assert_eq!(prev_participation.len(), n);
        debug_assert_eq!(curr_participation.len(), n);
        EpochBalances::sweep(
            current_epoch,
            (0..n).map(|i| EpochBalancesRow {
                activation_epoch: self.activation_epoch[i],
                exit_epoch: self.exit_epoch[i],
                slashed: self.is_slashed(i),
                effective_balance: self.effective_balance[i],
                previous_participation: prev_participation[i],
                current_participation: curr_participation[i],
            }),
        )
    }

    #[inline]
    pub fn find_by_pubkey(&self, pubkey: &BLSPubkey) -> Option<usize> {
        self.index.read().get(pubkey).map(|&idx| idx as usize)
    }

    /// Number of entries in the pubkey → idx index. Should equal
    /// `validator_count` post-`decompose` / `promote_into_base`.
    #[inline]
    pub fn index_len(&self) -> usize {
        self.index.read().len()
    }

    pub(super) fn leaf_hashes(&self, range: Range<usize>) -> Vec<B256> {
        let shared_fields = |i: usize| {
            let mut slashed = [0u8; 32];
            slashed[0] = u8::from(self.is_slashed(i));
            [
                self.val_withdrawal_credentials[i].0,
                uint64_chunk(self.effective_balance[i]),
                slashed,
                uint64_chunk(self.activation_eligibility_epoch[i]),
                uint64_chunk(self.activation_epoch[i]),
                uint64_chunk(self.exit_epoch[i]),
                uint64_chunk(self.withdrawable_epoch[i]),
            ]
        };
        match &self.scheme_keys {
            SchemeColumn::Bls(_) => {
                let pubkey_chunks = range.clone().flat_map(|i| {
                    let mut tail = [0u8; 32];
                    tail[..16].copy_from_slice(&self.val_pubkey[i][32..]);
                    [self.val_pubkey[i][..32].try_into().unwrap(), tail]
                });
                let pubkey_roots = merkleize_each(pubkey_chunks.collect(), 2);
                let fields = range.zip(pubkey_roots).flat_map(|(i, pubkey_root)| {
                    std::iter::once(pubkey_root).chain(shared_fields(i))
                });
                merkleize_each(fields.collect(), 8)
            }
            // Nine fields pad to a 16-leaf tree.
            SchemeColumn::Xmss(vrf_roots) => {
                let fields = range.flat_map(|i| {
                    [*xmss_pubkey(&self.val_pubkey[i]), vrf_roots[i]]
                        .into_iter()
                        .chain(shared_fields(i))
                        .chain([B256::default(); 16 - 9])
                });
                merkleize_each(fields.collect(), 16)
            }
        }
    }

    /// Harness-seeding constructor: builds a registry from `ValSeed`s whose
    /// pubkeys need not be valid BLS points (decompression falls back to
    /// default), which `try_new` would reject. Crate-internal test use only —
    /// the one bridge from test seeds to the private `build`; reached from
    /// other crates' tests only through `for_test`.
    pub(crate) fn with_validators(seeds: &[ValSeed]) -> Self {
        Self::build(KeyScheme::Bls, validator_capacity(seeds.len()), seeds.len(), |i| {
            let s = &seeds[i];
            Ok::<_, Infallible>(ValidatorInit {
                pubkey: s.pubkey,
                scheme_key: SchemeKey::Bls(PublicKey::from_bytes(&s.pubkey).unwrap_or_default()),
                credentials: s.withdrawal_credentials,
                effective_balance: s.effective_balance,
                slashed: false,
                activation_eligibility_epoch: FAR_FUTURE_EPOCH,
                activation_epoch: s.activation_epoch,
                exit_epoch: s.exit_epoch,
                withdrawable_epoch: FAR_FUTURE_EPOCH,
            })
        })
        .unwrap()
    }
}
