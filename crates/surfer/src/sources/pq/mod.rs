use std::path::Path;

use flux::{
    spine::SpineAdapter,
    tile::Tile,
    timing::{InternalMessage, Nanos},
};
use silver_common::{PqEvent, PqMergeVotes, SilverSpine};
use silver_stages::SlotClock;

pub use self::data::{Aggregate, JobOutcome, Member, PqData, TargetKey, TimeBase};

mod data;

/// Reads the aggregator's `pq_events` and `pq_merge_votes` queues.
struct PqTile {
    data: PqData,
}

impl Tile<SilverSpine> for PqTile {
    fn loop_body(&mut self, adapter: &mut SpineAdapter<SilverSpine>) {
        let data = &mut self.data;
        adapter.consume_internal_message(|message: &mut InternalMessage<PqEvent>, _| {
            data.apply(message.tracking_timestamp().publish_t(), *message.data());
        });
        adapter.consume_internal_message(|message: &mut InternalMessage<PqMergeVotes>, _| {
            data.apply_votes(message.data());
        });
    }
}

pub struct PqSource {
    tile: PqTile,
    adapter: SpineAdapter<SilverSpine>,
}

impl PqSource {
    pub fn open(base_dir: &Path, clock: &SlotClock, gloas: bool) -> Self {
        let tile = PqTile { data: PqData::new(clock, gloas) };
        // Queue handles are `Copy` and live in shmem, so the spine can drop
        // once the adapter has attached.
        let mut spine = SilverSpine::new_with_base_dir(base_dir, None);
        let adapter = SpineAdapter::connect_tile(&tile, &mut spine);
        Self { tile, adapter }
    }

    pub fn sample(&mut self, now: Nanos) {
        self.tile.loop_body(&mut self.adapter);
        let current = self.tile.data.time.slot_at(self.tile.data.time.ms(now));
        self.tile.data.prune(current);
    }

    pub fn data(&self) -> &PqData {
        &self.tile.data
    }
}
