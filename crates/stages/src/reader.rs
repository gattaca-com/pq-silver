use std::vec::Drain;

use flux::{spine::SpineAdapter, timing::InternalMessage};
use rustc_hash::FxHashMap;
use silver_common::{
    BeaconStateEvent, BlockStage, DataColumnsEvent, DataKind, EngineReq, EngineResp, SilverSpine,
    SyncNeed,
};

use crate::{Stage, StageEvent};

/// Past this many slots a root is dropped, and a later FCU naming it resolves
/// no slot.
const TRACKED_SLOTS: u64 = 64;

struct Tracked {
    slot: u64,
    received: bool,
    attestable: bool,
}

impl Tracked {
    fn new(slot: u64) -> Self {
        Self { slot, received: false, attestable: false }
    }
}

#[derive(Default)]
pub struct StageReader {
    roots: FxHashMap<[u8; 32], Tracked>,
    out: Vec<StageEvent>,
}

impl StageReader {
    pub fn consume(&mut self, adapter: &mut SpineAdapter<SilverSpine>) -> Drain<'_, StageEvent> {
        adapter.consume_internal_message(|m: &mut InternalMessage<BeaconStateEvent>, _| {
            self.on_beacon_state(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineReq>, _| {
            self.on_engine_req(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<EngineResp>, _| {
            self.on_engine_resp(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<DataColumnsEvent>, _| {
            self.on_data_columns(m);
        });
        adapter.consume_internal_message(|m: &mut InternalMessage<SyncNeed>, _| {
            self.on_sync_need(m);
        });
        self.out.drain(..)
    }

    fn on_beacon_state(&mut self, m: &InternalMessage<BeaconStateEvent>) {
        let ts = m.tracking_timestamp().publish_t();
        match *m.data() {
            BeaconStateEvent::BlockReceived { .. } => self.on_block_received(m),
            BeaconStateEvent::LocalAttestation { slot, block_root } => {
                let slot = Some(slot);
                self.out.push(StageEvent { stage: Stage::LocalAttestation, ts, block_root, slot })
            }
            BeaconStateEvent::BlockRejected { block_root, .. } => {
                let slot = self.slot_of(&block_root);
                self.out.push(StageEvent { stage: Stage::Rejected, ts, block_root, slot })
            }
            _ => {}
        }
    }

    /// A parked block is announced again from the replay that admits it, so
    /// only the first announcement is its arrival; the announcement whose
    /// handling ran the transition carries its stamp.
    fn on_block_received(&mut self, m: &InternalMessage<BeaconStateEvent>) {
        let BeaconStateEvent::BlockReceived { slot, block_root, source, stage, stf, .. } =
            *m.data()
        else {
            return;
        };
        // A repeat's timestamp does not date the original import or state
        // transition, even if the root is no longer tracked.
        if stage == BlockStage::AlreadyKnown {
            return;
        }

        self.roots.retain(|_, t| slot.saturating_sub(t.slot) < TRACKED_SLOTS);
        let tracked = self.roots.entry(block_root).or_insert(Tracked::new(slot));
        let event = |stage, ts| StageEvent { stage, ts, block_root, slot: Some(slot) };
        let published = m.tracking_timestamp().publish_t();

        if !tracked.received {
            tracked.received = true;
            self.out.push(event(Stage::Received { source }, m.ingestion_time().real()));
        }
        if let Some(stf) = stf {
            self.out.push(event(Stage::Validated, stf.validated_at));
            self.out.push(event(Stage::StfDone { gate: stf.gate }, published));
        }
        if stage == BlockStage::Applied && !tracked.attestable {
            tracked.attestable = true;
            self.out.push(event(Stage::Attestable, published));
        }
    }

    fn slot_of(&self, block_root: &[u8; 32]) -> Option<u64> {
        self.roots.get(block_root).map(|t| t.slot)
    }

    fn on_engine_req(&mut self, m: &InternalMessage<EngineReq>) {
        let (block_root, slot, source) = match *m.data() {
            EngineReq::NewPayload(req) => {
                self.roots.entry(req.block_root).or_insert(Tracked::new(req.slot));
                (req.block_root, Some(req.slot), req.block_source)
            }
            EngineReq::NewPayloadEnvelope(req) => {
                let slot = self.slot_of(&req.block_root);
                (req.block_root, slot, req.block_source)
            }
            _ => return,
        };
        self.out.push(StageEvent {
            stage: Stage::ElSent { source },
            ts: m.tracking_timestamp().publish_t(),
            block_root,
            slot,
        });
    }

    fn on_engine_resp(&mut self, m: &InternalMessage<EngineResp>) {
        let EngineResp::NewPayload(resp) = *m.data() else {
            return;
        };
        self.out.push(StageEvent {
            stage: Stage::ElVerdict { verdict: resp.status },
            ts: m.tracking_timestamp().publish_t(),
            block_root: resp.block_root,
            slot: self.slot_of(&resp.block_root),
        });
    }

    /// A sidecar is two events of one message: ingestion is its arrival
    /// on the wire, publish the moment it passed validation.
    fn on_data_columns(&mut self, m: &InternalMessage<DataColumnsEvent>) {
        match *m.data() {
            DataColumnsEvent::Validated { block_root, column_index, slot, origin, .. } => {
                self.roots.entry(block_root).or_insert(Tracked::new(slot));
                let recv = StageEvent {
                    stage: Stage::ColumnRecv { index: column_index, origin },
                    ts: m.ingestion_time().real(),
                    block_root,
                    slot: Some(slot),
                };
                self.out.push(recv);
                self.out.push(StageEvent {
                    stage: Stage::ColumnValidated { index: column_index, origin },
                    ts: m.tracking_timestamp().publish_t(),
                    ..recv
                });
            }
            DataColumnsEvent::Persist { .. } | DataColumnsEvent::Publish { .. } => {}
            DataColumnsEvent::Available { block_root, slot } => {
                self.out.push(StageEvent {
                    stage: Stage::DaAvailable,
                    ts: m.tracking_timestamp().publish_t(),
                    block_root,
                    slot: Some(slot),
                });
            }
        }
    }

    /// Custody completion is the sync engine's need closing, so it rides
    /// `SyncNeed` rather than `DataColumnsEvent`.
    fn on_sync_need(&mut self, m: &InternalMessage<SyncNeed>) {
        let SyncNeed::Arrived { root, slot, kind: DataKind::Columns } = *m.data() else {
            return;
        };
        self.out.push(StageEvent {
            stage: Stage::CustodyDone,
            ts: m.tracking_timestamp().publish_t(),
            block_root: root,
            slot: Some(slot),
        });
    }
}

#[cfg(test)]
mod tests {
    use flux::timing::{IngestionTime, Instant, Nanos, PublishDelta, TrackingTimestamp};
    use silver_common::{
        BlockSource, BlockStage, ColumnOrigin, DataKind, EngineNewPayloadEnvelopeReq,
        EngineNewPayloadReq, EngineNewPayloadResp, MAX_BLOBS_PER_BLOCK, PayloadValidationStatus,
        SszCache, StfGate, StfStamp, TCache, TCacheId, TCacheProducer, TCacheRead,
    };

    use super::*;
    use crate::test_clock::at;

    /// Internal-clock ticks between ingestion and publish. Ticks are TSC, so
    /// the nanoseconds they become are calibration-dependent — assert ordering
    /// against the ingestion time, not an exact value.
    const PUBLISH_TICKS: u64 = 10_000_000;

    fn msg<T>(data: T, ingestion: Nanos) -> InternalMessage<T> {
        let ts = TrackingTimestamp {
            ingestion_t: IngestionTime::new(ingestion, Instant(0)),
            publish_delta: PublishDelta::new(0)
                .from_ingestion_and_publish_t(Instant(0), Instant(PUBLISH_TICKS)),
        };
        InternalMessage::new(ts, data)
    }

    fn unread_payload() -> TCacheRead {
        let mut producer = TCache::producer(TCacheId::NetworkIngress, 1 << 12);
        let mut r = producer.reserve(1, true).expect("tcache reserve");
        r.increment_offset(1);
        r.read()
    }

    fn block_received(
        root: [u8; 32],
        slot: u64,
        source: BlockSource,
        stage: BlockStage,
        stf: Option<StfStamp>,
    ) -> BeaconStateEvent {
        BeaconStateEvent::BlockReceived {
            slot,
            block_root: root,
            stage,
            source,
            parent_slot: None,
            parent_empty: false,
            stf,
        }
    }

    fn stamp(validated_at: Nanos, gate: StfGate) -> Option<StfStamp> {
        Some(StfStamp { validated_at, gate })
    }

    fn parked(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        block_received(root, slot, source, BlockStage::AwaitParent, None)
    }

    /// The announcement whose handling validated and applied the block.
    fn applied(root: [u8; 32], slot: u64, validated_at: Nanos) -> BeaconStateEvent {
        let stf = stamp(validated_at, StfGate::Now);
        block_received(root, slot, BlockSource::Gossip, BlockStage::Applied, stf)
    }

    /// A later announcement of an import: a held block's release, a duplicate.
    fn imported(root: [u8; 32], slot: u64, source: BlockSource) -> BeaconStateEvent {
        block_received(root, slot, source, BlockStage::Applied, None)
    }

    fn new_payload(root: [u8; 32], slot: u64, block_source: BlockSource) -> EngineReq {
        EngineReq::NewPayload(EngineNewPayloadReq {
            data: unread_payload(),
            block_root: root,
            slot,
            block_source,
        })
    }

    fn verdict(root: [u8; 32], status: PayloadValidationStatus) -> EngineResp {
        EngineResp::NewPayload(EngineNewPayloadResp {
            block_root: root,
            status,
            latest_valid_hash: None,
        })
    }

    fn validated(root: [u8; 32], slot: u64, column_index: u64) -> DataColumnsEvent {
        DataColumnsEvent::Validated {
            block_root: root,
            column_index,
            slot,
            origin: ColumnOrigin::Gossip,
            ssz: unread_payload(),
            ssz_cache: SszCache::Gossip,
        }
    }

    fn stages(out: &[StageEvent]) -> Vec<&'static str> {
        out.iter().map(|o| o.stage.name()).collect()
    }

    fn find<'a>(out: &'a [StageEvent], stage: &str) -> &'a StageEvent {
        out.iter().find(|o| o.stage.name() == stage).unwrap_or_else(|| panic!("no {stage}"))
    }

    #[test]
    fn block_flow_stages() {
        let mut reader = StageReader::default();
        let root = [1u8; 32];

        reader.on_beacon_state(&msg(applied(root, 2, at(2, 304)), at(2, 300)));
        reader.on_engine_req(&msg(new_payload(root, 2, BlockSource::Gossip), at(2, 300)));
        reader.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(2, 520)));

        assert_eq!(stages(&reader.out), [
            "received",
            "validated",
            "stf_done",
            "attestable",
            "el_sent",
            "el_verdict"
        ]);
        assert!(reader.out.iter().all(|o| o.block_root == root));
        assert!(
            reader.out.iter().all(|o| o.slot == Some(2)),
            "the verdict slot resolves via the map"
        );

        let received = find(&reader.out, "received");
        assert_eq!(received.ts, at(2, 300), "arrival is the ingestion clock");
        assert!(matches!(received.stage, Stage::Received { source: BlockSource::Gossip }));
        assert_eq!(find(&reader.out, "validated").ts, at(2, 304), "the node's stamp");
        assert!(matches!(find(&reader.out, "stf_done").stage, Stage::StfDone {
            gate: StfGate::Now
        }));
        assert!(matches!(find(&reader.out, "el_verdict").stage, Stage::ElVerdict {
            verdict: PayloadValidationStatus::Valid
        }));

        // The remaining stages are publish events of their message, so
        // each lands after the ingestion time it was built from.
        for (stage, ingested) in [
            ("stf_done", at(2, 300)),
            ("attestable", at(2, 300)),
            ("el_sent", at(2, 300)),
            ("el_verdict", at(2, 520)),
        ] {
            let t = find(&reader.out, stage).ts;
            assert!(t > ingested, "{stage} at {t} must follow its ingestion {ingested}");
        }
    }

    #[test]
    fn a_local_vote_is_a_stage_of_the_block_it_votes_for() {
        let mut reader = StageReader::default();
        let root = [3u8; 32];
        let vote = BeaconStateEvent::LocalAttestation { slot: 6, block_root: root };
        reader.on_beacon_state(&msg(vote, at(6, 500)));

        let [event] = reader.out.as_slice() else { panic!("one stage") };
        assert_eq!(event.stage.name(), "local_attestation");
        assert_eq!((event.block_root, event.slot), (root, Some(6)));
    }

    #[test]
    fn a_repeat_receipt_of_an_imported_block_adds_no_stage() {
        let mut reader = StageReader::default();
        let root = [7u8; 32];
        reader.on_beacon_state(&msg(applied(root, 2, at(2, 304)), at(2, 300)));
        let after_import = stages(&reader.out);

        let repeat = block_received(root, 2, BlockSource::Rpc, BlockStage::AlreadyKnown, None);
        reader.on_beacon_state(&msg(repeat, at(2, 900)));
        assert_eq!(stages(&reader.out), after_import);

        let untracked = [8u8; 32];
        let repeat = block_received(untracked, 1, BlockSource::Rpc, BlockStage::AlreadyKnown, None);
        reader.on_beacon_state(&msg(repeat, at(2, 950)));
        assert_eq!(stages(&reader.out), after_import);
        assert!(!reader.roots.contains_key(&untracked));
    }

    /// The replay that admits a parked block announces it again, at that
    /// replay's clock: the arrival keeps the park, the import is the release.
    #[test]
    fn parked_block_is_received_at_park_and_imported_at_release() {
        let mut reader = StageReader::default();
        let root = [3u8; 32];

        reader.on_beacon_state(&msg(parked(root, 5, BlockSource::Gossip), at(5, 400)));
        reader.on_beacon_state(&msg(applied(root, 5, at(5, 3_102)), at(5, 3_100)));

        assert_eq!(stages(&reader.out), ["received", "validated", "stf_done", "attestable"]);
        assert_eq!(reader.out[0].ts, at(5, 400), "one arrival per root");
        assert_eq!(reader.out[1].ts, at(5, 3_102), "validated in the release's handling");
        assert!(reader.out[2].ts > at(5, 3_100), "import is the release's publish");
        assert_eq!(reader.out[2].ts, reader.out[3].ts, "ungated: one publish carries both");
    }

    /// A gate held the import: the post-state lands with the held
    /// announcement, which names the gate; the import with the `Applied`
    /// that follows; a re-fetch while held repeats neither.
    #[test]
    fn held_block_splits_stf_done_from_attestable() {
        for (stage, gate) in
            [(BlockStage::AwaitData, StfGate::Data), (BlockStage::AwaitVerify, StfGate::Verify)]
        {
            let mut reader = StageReader::default();
            let root = [10u8; 32];
            let held = |source, stf| block_received(root, 5, source, stage, stf);

            let first = held(BlockSource::Gossip, stamp(at(5, 402), gate));
            reader.on_beacon_state(&msg(first, at(5, 400)));
            reader.on_beacon_state(&msg(held(BlockSource::Rpc, None), at(5, 500)));
            reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Gossip), at(5, 700)));

            assert_eq!(stages(&reader.out), ["received", "validated", "stf_done", "attestable"]);
            assert_eq!(reader.out[0].ts, at(5, 400));
            assert!(matches!(reader.out[2].stage, Stage::StfDone { gate: g } if g == gate));
            let stf_done = reader.out[2].ts;
            assert!(stf_done > at(5, 400) && stf_done < at(5, 500), "the first held publish");
            assert!(reader.out[3].ts > at(5, 700), "the Applied publish");
        }
    }

    /// Without the stamp of the handling that ran the transition (a reader
    /// attached after it), the import alone is known.
    #[test]
    fn an_unstamped_import_has_no_transition() {
        let mut reader = StageReader::default();
        let root = [12u8; 32];
        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Gossip), at(5, 700)));
        assert_eq!(stages(&reader.out), ["received", "attestable"]);
    }

    #[test]
    fn a_rejection_closes_a_tracked_block() {
        let mut reader = StageReader::default();
        let root = [13u8; 32];
        let held = block_received(
            root,
            5,
            BlockSource::Gossip,
            BlockStage::AwaitVerify,
            stamp(at(5, 402), StfGate::Verify),
        );
        reader.on_beacon_state(&msg(held, at(5, 400)));
        let rejected =
            BeaconStateEvent::BlockRejected { block_root: root, source: BlockSource::Gossip };
        reader.on_beacon_state(&msg(rejected, at(5, 800)));

        let last = reader.out.last().expect("stages");
        assert_eq!((last.stage.name(), last.slot), ("rejected", Some(5)));
        assert!(last.ts > at(5, 800));

        let untracked =
            BeaconStateEvent::BlockRejected { block_root: [14u8; 32], source: BlockSource::Rpc };
        reader.on_beacon_state(&msg(untracked, at(5, 900)));
        assert_eq!(reader.out.last().expect("stages").slot, None);
    }

    /// A duplicate of an imported block is announced `Applied` again.
    #[test]
    fn duplicate_import_announcements_emit_once() {
        let mut reader = StageReader::default();
        let root = [8u8; 32];

        reader.on_beacon_state(&msg(applied(root, 5, at(5, 402)), at(5, 400)));
        reader.on_beacon_state(&msg(imported(root, 5, BlockSource::Rpc), at(5, 900)));

        assert_eq!(stages(&reader.out), ["received", "validated", "stf_done", "attestable"]);
        assert_eq!(reader.out[0].ts, at(5, 400));
        assert!(reader.out[3].ts < at(5, 900));
    }

    /// `NewPayload` carries the slot, so a verdict resolves even when the
    /// arrival predates attach.
    #[test]
    fn new_payload_seeds_the_slot() {
        let mut reader = StageReader::default();
        let root = [4u8; 32];

        reader.on_engine_req(&msg(new_payload(root, 6, BlockSource::Rpc), at(6, 500)));
        reader.on_engine_resp(&msg(verdict(root, PayloadValidationStatus::Valid), at(6, 600)));

        assert_eq!(find(&reader.out, "el_verdict").slot, Some(6));
    }

    /// A Gloas payload reaches the EL with its envelope, after the block
    /// that seeded the slot.
    #[test]
    fn envelope_new_payload_is_el_sent() {
        let mut reader = StageReader::default();
        let root = [11u8; 32];
        let envelope = EngineReq::NewPayloadEnvelope(EngineNewPayloadEnvelopeReq {
            data: unread_payload(),
            block_root: root,
            block_source: BlockSource::Rpc,
            hash_count: 0,
            versioned_hashes: [[0; 32]; MAX_BLOBS_PER_BLOCK],
        });

        reader.on_beacon_state(&msg(imported(root, 7, BlockSource::Gossip), at(7, 300)));
        reader.on_engine_req(&msg(envelope, at(7, 1_200)));

        let sent = find(&reader.out, "el_sent");
        assert!(matches!(sent.stage, Stage::ElSent { source: BlockSource::Rpc }));
        assert_eq!(sent.slot, Some(7));
    }

    #[test]
    fn roots_age_out_of_slot_resolution() {
        let mut reader = StageReader::default();
        let old = [5u8; 32];

        reader.on_beacon_state(&msg(parked(old, 0, BlockSource::Gossip), at(0, 300)));
        reader.on_beacon_state(&msg(parked([6u8; 32], 100, BlockSource::Gossip), at(100, 300)));
        reader.on_engine_resp(&msg(verdict(old, PayloadValidationStatus::Valid), at(100, 460)));

        assert_eq!(find(&reader.out, "el_verdict").slot, None, "evicted after 64 slots");
    }

    #[test]
    fn custody_completion_is_the_columns_arrival_only() {
        let mut reader = StageReader::default();
        let root = [9u8; 32];
        let arrived = |kind| SyncNeed::Arrived { root, slot: 3, kind };

        reader.on_sync_need(&msg(arrived(DataKind::Block), at(3, 200)));
        reader.on_sync_need(&msg(arrived(DataKind::Columns), at(3, 900)));

        assert_eq!(stages(&reader.out), ["custody_done"]);
        assert_eq!(reader.out[0].slot, Some(3));
        assert!(reader.out[0].ts > at(3, 900));
    }

    #[test]
    fn sidecars_record_arrival_then_validation() {
        let mut reader = StageReader::default();
        let root = [7u8; 32];

        reader.on_data_columns(&msg(validated(root, 3, 48), at(3, 1_400)));
        reader.on_data_columns(&msg(
            DataColumnsEvent::Available { block_root: root, slot: 3 },
            at(3, 1_500),
        ));

        assert_eq!(stages(&reader.out), ["column_recv", "column_validated", "da_available"]);
        assert!(reader.out.iter().all(|o| o.block_root == root && o.slot == Some(3)));

        let recv = find(&reader.out, "column_recv");
        assert!(matches!(recv.stage, Stage::ColumnRecv {
            index: 48,
            origin: ColumnOrigin::Gossip
        }));
        assert_eq!(recv.ts, at(3, 1_400), "arrival is the ingestion clock");

        let validated = find(&reader.out, "column_validated");
        assert!(matches!(validated.stage, Stage::ColumnValidated { index: 48, .. }));
        assert!(validated.ts > recv.ts, "validation follows arrival");
    }
}
