use rustc_hash::FxHashMap;
use silver_beacon_state_data::B256;
use silver_common::ssz_view::BUILDER_EXIT_REQUEST_SIZE;

use crate::stf::RequestsLayout;

/// Execution requests of verified payloads, by block root, as the SSZ
/// `ExecutionRequests` the envelope carried. A child building on a payload
/// applies them; its block's post-state never does. Payloads without requests
/// have no entry.
#[derive(Default)]
pub(super) struct PayloadExecutionRequests(FxHashMap<B256, Box<[u8]>>);

impl PayloadExecutionRequests {
    /// `requests` passed `verify_execution_payload_envelope`, which bounds
    /// and roots them.
    pub fn insert(&mut self, block_root: B256, (requests, layout): (&[u8], RequestsLayout)) {
        if layout.sections(requests).iter().any(|section| !section.is_empty()) {
            self.0.insert(block_root, requests.into());
        }
    }

    /// The `parent_execution_requests` of a block building on this payload.
    pub fn get(&self, block_root: &B256, layout: RequestsLayout) -> &[u8] {
        self.0.get(block_root).map_or(layout.empty(), |requests| requests)
    }

    pub fn builder_exits(
        &self,
        block_root: &B256,
        layout: RequestsLayout,
    ) -> impl Iterator<Item = &[u8; BUILDER_EXIT_REQUEST_SIZE]> {
        let [_, _, _, _, builder_exits, ..] = layout.sections(self.get(block_root, layout));
        builder_exits
            .chunks_exact(BUILDER_EXIT_REQUEST_SIZE)
            .map(|request| request.try_into().expect("BUILDER_EXIT_REQUEST_SIZE bytes"))
    }

    pub fn drop_outdated(&mut self, is_live: impl Fn(&B256) -> bool) {
        self.0.retain(|block_root, _| is_live(block_root));
    }
}

#[cfg(test)]
mod tests {
    use silver_common::ssz_view::VOLUNTARY_EXIT_REQUEST_SIZE;

    use super::*;

    /// One builder exit, then one voluntary exit where the layout has the list.
    fn one_builder_exit(layout: RequestsLayout, fill: u8) -> Vec<u8> {
        let lists = match layout {
            RequestsLayout::Gloas => 5,
            RequestsLayout::Pq => 8,
        };
        let start = 4 * lists as u32;
        let exits_end = start + BUILDER_EXIT_REQUEST_SIZE as u32;
        let offsets = (0..lists).map(|list| if list <= 4 { start } else { exits_end });
        let mut ssz: Vec<u8> = offsets.flat_map(u32::to_le_bytes).collect();
        ssz.extend_from_slice(&[fill; BUILDER_EXIT_REQUEST_SIZE]);
        if lists == 8 {
            ssz.extend_from_slice(&[!fill; VOLUNTARY_EXIT_REQUEST_SIZE]);
        }
        ssz
    }

    #[test]
    fn only_payloads_with_requests_are_held() {
        for layout in [RequestsLayout::Gloas, RequestsLayout::Pq] {
            let mut requests = PayloadExecutionRequests::default();
            requests.insert([1; 32], (layout.empty(), layout));
            assert!(requests.0.is_empty());
            assert_eq!(requests.get(&[1; 32], layout), layout.empty());
            assert_eq!(requests.builder_exits(&[1; 32], layout).count(), 0);

            let exit = one_builder_exit(layout, 7);
            assert!(layout.check_canonical(&exit));
            requests.insert([2; 32], (&exit, layout));
            assert_eq!(requests.get(&[2; 32], layout), exit);
            assert_eq!(requests.builder_exits(&[2; 32], layout).collect::<Vec<_>>(), [
                &[7; BUILDER_EXIT_REQUEST_SIZE]
            ]);

            requests.drop_outdated(|root| *root != [2; 32]);
            assert_eq!(requests.get(&[2; 32], layout), layout.empty());
        }
    }

    #[test]
    fn the_empty_container_roots_to_the_empty_requests_root() {
        for layout in [RequestsLayout::Gloas, RequestsLayout::Pq] {
            assert_eq!(layout.hash_tree_root(layout.empty()), layout.empty_root());
        }
    }
}
