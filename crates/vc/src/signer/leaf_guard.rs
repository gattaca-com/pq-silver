use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{FileExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use silver_common::{
    Error,
    xmss::{SlotDuty, attestation_leaf},
};

/// Attestations share one class; each of a slot's eight leaves has its own.
const CLASSES: usize = 1 + 8;
const ENTRY_LEN: usize = size_of::<u32>() + 32;
const RECORD_LEN: usize = CLASSES * ENTRY_LEN;

/// The last leaf a class signed at and the root it signed there. Leaf 0 is
/// reserved, so no class ever signs at it: it marks an empty entry.
#[derive(Clone, Copy, Default)]
struct Signed {
    leaf: u32,
    root: [u8; 32],
}

/// Refuses to sign two roots at one leaf, which would expose that leaf and
/// let anyone forge at it. Within a class, leaves only ascend, so the last
/// one signed is the whole record.
pub struct LeafGuard {
    signed: Vec<[Signed; CLASSES]>,
}

impl LeafGuard {
    /// Opens each key's record, creating a missing one only if `create`: a
    /// record lost while its key signed elsewhere would let a leaf sign twice.
    /// It must move with the key.
    pub fn open(
        paths: impl IntoIterator<Item = PathBuf>,
        create: bool,
    ) -> Result<(Self, Vec<File>), Error> {
        let mut signed = Vec::new();
        let mut files = Vec::new();
        for path in paths {
            if !create && !path.exists() {
                return Err(Error::ConfigError(format!(
                    "no leaf record {}: pass --init-leaf-records only for keys that never signed with another record",
                    path.display()
                )));
            }
            let (record, file) = open_record(&path)
                .map_err(|e| Error::ConfigError(format!("leaf record {}: {e}", path.display())))?;
            signed.push(record);
            files.push(file);
        }
        Ok((Self { signed }, files))
    }

    /// Records a new leaf in `file`, unsynced: the signer syncs it before the
    /// signature leaves the process. Re-signing the recorded root is allowed,
    /// since signing is deterministic.
    pub fn admit(&mut self, key: usize, leaf: u32, root: &[u8; 32], file: &File) -> bool {
        let Some(class) = class_of(leaf) else {
            silver_log::error!(leaf, "not signed: leaf outside the duty ranges");
            return false;
        };
        let last = &mut self.signed[key][class];
        if leaf < last.leaf {
            // A duty asked again after a restart, its leaf already passed.
            silver_log::warn!(leaf, last = last.leaf, "not signed: leaf below the last signed");
            return false;
        }
        if leaf == last.leaf && *root != last.root {
            silver_log::error!(leaf, "not signed: leaf already signed another root");
            return false;
        }
        if leaf == last.leaf {
            return true;
        }
        let mut entry = [0; ENTRY_LEN];
        entry[..4].copy_from_slice(&leaf.to_le_bytes());
        entry[4..].copy_from_slice(root);
        if let Err(error) = file.write_all_at(&entry, (class * ENTRY_LEN) as u64) {
            silver_log::error!(%error, leaf, "not signed: leaf record not written");
            return false;
        }
        *last = Signed { leaf, root: *root };
        true
    }
}

/// `None` for a reserved or builder-bid leaf: a bid leaf counted as an
/// attestation would raise its class past every epoch's leaf.
fn class_of(leaf: u32) -> Option<usize> {
    let first_slot_leaf = SlotDuty::BeaconProposer.leaf(0).expect("slot 0 has leaves");
    let attestation_leaves = attestation_leaf(0).expect("epoch 0 has a leaf")..=
        attestation_leaf((1 << 29) - 1).expect("the last epoch with a leaf");
    match leaf.checked_sub(first_slot_leaf) {
        Some(offset) => Some(1 + (offset % 8) as usize),
        None => attestation_leaves.contains(&leaf).then_some(0),
    }
}

fn open_record(path: &Path) -> std::io::Result<([Signed; CLASSES], File)> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let mut bytes = [0; RECORD_LEN];
    match file.metadata()?.len() {
        0 => {
            file.write_all_at(&bytes, 0)?;
            file.sync_all()?;
        }
        len if len == RECORD_LEN as u64 => file.read_exact(&mut bytes)?,
        len => {
            let why = format!("{len} bytes, expected {RECORD_LEN}");
            return Err(std::io::Error::other(why));
        }
    }
    let record = std::array::from_fn(|class| {
        let entry = &bytes[class * ENTRY_LEN..][..ENTRY_LEN];
        Signed {
            leaf: u32::from_le_bytes(entry[..4].try_into().expect("4 bytes")),
            root: entry[4..].try_into().expect("32 bytes"),
        }
    });
    Ok((record, file))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(dir: &Path) -> (LeafGuard, Vec<File>) {
        LeafGuard::open([dir.join("a.leaves")], true).unwrap()
    }

    #[test]
    fn a_leaf_signs_one_root_and_leaves_only_ascend() {
        let dir = tempfile::tempdir().unwrap();
        let (mut guard, files) = guard(dir.path());
        let attestation = attestation_leaf(10).unwrap();
        assert!(guard.admit(0, attestation, &[1; 32], &files[0]));
        assert!(guard.admit(0, attestation, &[1; 32], &files[0]), "the same root again");
        assert!(!guard.admit(0, attestation, &[2; 32], &files[0]), "another root");
        assert!(!guard.admit(0, attestation_leaf(9).unwrap(), &[3; 32], &files[0]));
        assert!(guard.admit(0, attestation_leaf(11).unwrap(), &[4; 32], &files[0]));
    }

    #[test]
    fn each_slot_duty_has_its_own_class() {
        let dir = tempfile::tempdir().unwrap();
        let (mut guard, files) = guard(dir.path());
        let block = SlotDuty::BeaconProposer.leaf(100).unwrap();
        let aggregate = SlotDuty::AggregateAndProof.leaf(99).unwrap();
        assert!(guard.admit(0, block, &[1; 32], &files[0]));
        assert!(guard.admit(0, aggregate, &[2; 32], &files[0]), "an older slot, another duty");
        assert!(guard.admit(0, attestation_leaf(1).unwrap(), &[3; 32], &files[0]));
        assert!(!guard.admit(0, SlotDuty::BeaconProposer.leaf(99).unwrap(), &[4; 32], &files[0]));
        assert!(!guard.admit(0, 5, &[5; 32], &files[0]), "a reserved leaf");
        let bid = attestation_leaf((1 << 29) - 1).unwrap() + 1;
        assert!(!guard.admit(0, bid, &[6; 32], &files[0]), "a builder-bid leaf");
        assert!(guard.admit(0, attestation_leaf(2).unwrap(), &[7; 32], &files[0]));
    }

    #[test]
    fn the_record_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let leaf = SlotDuty::ProposerPreferences.leaf(70).unwrap();
        {
            let (mut guard, files) = guard(dir.path());
            assert!(guard.admit(0, leaf, &[1; 32], &files[0]));
        }
        let (mut guard, files) = guard(dir.path());
        assert!(!guard.admit(0, leaf, &[2; 32], &files[0]));
        assert!(guard.admit(0, leaf, &[1; 32], &files[0]));
        assert_eq!(files[0].metadata().unwrap().len(), RECORD_LEN as u64);

        std::fs::write(dir.path().join("b.leaves"), [0; 7]).unwrap();
        assert!(LeafGuard::open([dir.path().join("b.leaves")], true).is_err());
        assert!(LeafGuard::open([dir.path().join("c.leaves")], false).is_err(), "not created");
    }
}
