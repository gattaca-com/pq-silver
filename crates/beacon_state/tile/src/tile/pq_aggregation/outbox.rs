use flux::spine::SpineProducers;
use silver_common::{PqEvent, PqMergeVotes};

use crate::tile::Producers;

/// Events for surfer, held until the tile hands over its producers. The
/// buffers keep their capacity across loops.
#[derive(Default)]
pub(super) struct Outbox {
    events: Vec<PqEvent>,
    votes: Vec<PqMergeVotes>,
}

impl Outbox {
    pub(super) fn push(&mut self, event: PqEvent) {
        self.events.push(event);
    }

    pub(super) fn push_votes(&mut self, votes: PqMergeVotes) {
        self.votes.push(votes);
    }

    pub(super) fn flush(&mut self, producers: &mut Producers) {
        for event in self.events.drain(..) {
            producers.produce(event);
        }
        for votes in self.votes.drain(..) {
            producers.produce(votes);
        }
    }
}
