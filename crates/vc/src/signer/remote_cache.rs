use std::{collections::HashMap, fs, io::Read, ops::Range, path::Path, thread, time::Duration};

use lean_xmss::internals::{CACHED_BOTTOM_SIZE, CACHED_TREE_SIZE};
use silver_beacon_state_data::pq_validator_pubkeys;
use silver_common::ssz_view::XMSSPubkey;

/// A top tree and the first attestation and slot-duty bottom trees.
pub const RECORD_LEN: usize = CACHED_TREE_SIZE + 2 * CACHED_BOTTOM_SIZE;
/// The companion `.bin`: each genesis validator's pubkey, then its VRF root.
const METADATA_RECORD_LEN: usize = 32 + 32;
const MAX_METADATA_LEN: usize = 1 << 24;
/// About 0.9 MiB a request. The devnet's server takes ~0.85 s a request
/// whatever its size (Teku's measurement), so records come in runs.
const MAX_RUN: usize = 64;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ATTEMPTS: usize = 3;
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// The devnet's precomputed expanded keys (`<name>.xmss`), one record per
/// genesis validator in the order of `<name>.bin`.
///
/// `from_cache_bytes` checks a record only against the pubkey it is given,
/// so pubkeys come from the network's own `genesis.ssz`: `.bin` only says
/// where each key's record is.
pub struct RemoteCache {
    agent: ureq::Agent,
    url: String,
    /// Each genesis key's record index, by its public parameter, which a seed
    /// derives without building a tree.
    by_parameter: HashMap<[u8; 16], (usize, XMSSPubkey)>,
}

/// Records at consecutive indices, fetched in one request.
pub struct Run {
    first: usize,
    /// Each record's key: its position in the caller's list, and its pubkey.
    keys: Vec<(usize, XMSSPubkey)>,
}

impl RemoteCache {
    pub fn open(url: &str, genesis_state: Option<&Path>) -> Result<Self, String> {
        let genesis_state = genesis_state.ok_or("needs the network's genesis.ssz")?;
        let state =
            fs::read(genesis_state).map_err(|e| format!("{}: {e}", genesis_state.display()))?;
        let genesis = pq_validator_pubkeys(&state).map_err(|e| format!("genesis registry: {e}"))?;
        Self::with_registry(url, genesis.copied())
    }

    /// `registry` is the genesis validators' pubkeys, in index order.
    pub fn with_registry(
        url: &str,
        registry: impl Iterator<Item = XMSSPubkey>,
    ) -> Result<Self, String> {
        let registered = by_parameter(registry.enumerate());

        let metadata_url = url
            .strip_suffix(".xmss")
            .map(|stem| format!("{stem}.bin"))
            .ok_or("the cache URL does not end in .xmss")?;
        let agent = ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build();
        let metadata = get(&agent, &metadata_url, None, MAX_METADATA_LEN)?;
        let (records, []) = metadata.as_chunks::<METADATA_RECORD_LEN>() else {
            return Err(format!("{metadata_url} is not whole {METADATA_RECORD_LEN}-byte records"));
        };
        let listed = records.iter().map(|record| *record.first_chunk().expect("32 bytes"));
        let mut by_parameter = by_parameter(listed.enumerate());
        let before = by_parameter.len();
        by_parameter.retain(|parameter, (_, pubkey)| {
            registered.get(parameter).is_some_and(|(_, registered)| registered == pubkey)
        });
        let unregistered = before - by_parameter.len();
        if unregistered > 0 {
            silver_log::warn!(unregistered, url = metadata_url, "listed keys not in genesis");
        }
        Ok(Self { agent, url: url.to_owned(), by_parameter })
    }

    /// The runs holding the records of `parameters`. A key without a genesis
    /// record is in none.
    pub fn runs(&self, parameters: &[[u8; 16]]) -> Vec<Run> {
        let mut wanted: Vec<_> = parameters
            .iter()
            .enumerate()
            .filter_map(|(position, parameter)| {
                let &(index, pubkey) = self.by_parameter.get(parameter)?;
                Some((index, position, pubkey))
            })
            .collect();
        wanted.sort_unstable_by_key(|&(index, ..)| index);
        wanted.dedup_by_key(|&mut (index, ..)| index);

        let mut runs: Vec<Run> = Vec::new();
        for (index, position, pubkey) in wanted {
            match runs.last_mut() {
                Some(run) if run.first + run.keys.len() == index && run.keys.len() < MAX_RUN => {
                    run.keys.push((position, pubkey))
                }
                _ => runs.push(Run { first: index, keys: vec![(position, pubkey)] }),
            }
        }
        runs
    }

    /// Each record of `run`, in order.
    pub fn fetch<'a>(
        &self,
        run: &'a Run,
    ) -> Result<impl Iterator<Item = (usize, XMSSPubkey, Vec<u8>)> + 'a, String> {
        let start = run.first * RECORD_LEN;
        let len = run.keys.len() * RECORD_LEN;
        let mut attempt = 1;
        let bytes = loop {
            match get(&self.agent, &self.url, Some(start..start + len), len) {
                Ok(bytes) if bytes.len() == len => break bytes,
                Ok(bytes) => return Err(format!("{} bytes, expected {len}", bytes.len())),
                Err(error) if attempt == ATTEMPTS => return Err(error),
                Err(_) => {
                    attempt += 1;
                    thread::sleep(RETRY_AFTER);
                }
            }
        };
        let records = bytes.chunks_exact(RECORD_LEN).map(<[u8]>::to_vec).collect::<Vec<_>>();
        Ok(run
            .keys
            .iter()
            .zip(records)
            .map(|(&(position, pubkey), record)| (position, pubkey, record)))
    }
}

/// A parameter two keys share identifies neither.
fn by_parameter(
    pubkeys: impl Iterator<Item = (usize, XMSSPubkey)>,
) -> HashMap<[u8; 16], (usize, XMSSPubkey)> {
    let mut found = HashMap::new();
    let mut shared = Vec::new();
    for (index, pubkey) in pubkeys {
        let parameter = *pubkey.last_chunk().expect("16 bytes");
        if found.insert(parameter, (index, pubkey)).is_some() {
            shared.push(parameter);
        }
    }
    for parameter in shared {
        found.remove(&parameter);
    }
    found
}

/// At most `max` bytes. A ranged request must be answered with only that
/// range, so a server that ignores `Range` cannot make us read the whole file.
fn get(
    agent: &ureq::Agent,
    url: &str,
    range: Option<Range<usize>>,
    max: usize,
) -> Result<Vec<u8>, String> {
    let mut request = agent.get(url).set("Accept-Encoding", "identity");
    if let Some(range) = &range {
        request = request.set("Range", &format!("bytes={}-{}", range.start, range.end - 1));
    }
    let response = request.call().map_err(|e| e.to_string())?;
    let expected = if range.is_some() { 206 } else { 200 };
    if response.status() != expected {
        return Err(format!("HTTP {} from {url}, expected {expected}", response.status()));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > max {
        return Err(format!("{url} sent more than {max} bytes"));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(listed: &[XMSSPubkey]) -> RemoteCache {
        RemoteCache {
            agent: ureq::agent(),
            url: String::new(),
            by_parameter: by_parameter(listed.iter().copied().enumerate()),
        }
    }

    fn key(index: u8) -> XMSSPubkey {
        let mut pubkey = [0; 32];
        pubkey[16] = index;
        pubkey[0] = 0xff;
        pubkey
    }

    #[test]
    fn records_group_into_runs_of_consecutive_indices() {
        let listed: Vec<_> = (0..200).map(|i| key(i as u8)).collect();
        let cache = cache(&listed);
        let parameter = |i: u8| *key(i).last_chunk().unwrap();
        let wanted = [5, 3, 4, 9, 150, 151, 199].map(parameter);
        let runs = cache.runs(&wanted);
        let shape = runs.iter().map(|run| (run.first, run.keys.len())).collect::<Vec<_>>();
        assert_eq!(shape, [(3, 3), (9, 1), (150, 2), (199, 1)]);
        assert_eq!(runs[0].keys[0].0, 1, "positions follow the caller's list");

        let all: Vec<_> = (0..200).map(|i| parameter(i as u8)).collect();
        let lengths = cache.runs(&all).iter().map(|run| run.keys.len()).collect::<Vec<_>>();
        assert_eq!(lengths, [64, 64, 64, 8]);
    }

    #[test]
    fn a_shared_parameter_identifies_no_key() {
        let mut twin = key(1);
        twin[0] = 0xee;
        let cache = cache(&[key(1), twin, key(2)]);
        assert_eq!(cache.runs(&[*key(1).last_chunk().unwrap()]).len(), 0);
        assert_eq!(cache.runs(&[*key(2).last_chunk().unwrap()]).len(), 1);
    }
}
