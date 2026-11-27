/// A block produced with its payload: the block, its envelope, and the
/// envelope's blobs with their cell proofs.
pub struct BlockContents<'a> {
    pub block: &'a [u8],
    pub envelope: &'a [u8],
    pub kzg_proofs: &'a [u8],
    pub blobs: &'a [u8],
}

impl<'a> BlockContents<'a> {
    pub const FIXED: usize = 4 * 4;

    pub fn parse(buf: &'a [u8]) -> Option<Self> {
        let fixed = buf.get(..Self::FIXED)?;
        let at: [usize; 4] = std::array::from_fn(|i| {
            u32::from_le_bytes(fixed[4 * i..4 * i + 4].try_into().expect("4 bytes")) as usize
        });
        if at[0] != Self::FIXED || !at.is_sorted() || at[3] > buf.len() {
            return None;
        }
        Some(Self {
            block: &buf[at[0]..at[1]],
            envelope: &buf[at[1]..at[2]],
            kzg_proofs: &buf[at[2]..at[3]],
            blobs: &buf[at[3]..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(parts: [&[u8]; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut at = BlockContents::FIXED;
        for part in parts {
            out.extend_from_slice(&(at as u32).to_le_bytes());
            at += part.len();
        }
        parts.iter().for_each(|part| out.extend_from_slice(part));
        out
    }

    #[test]
    fn splits_at_its_offsets_and_refuses_misframing() {
        let buf = framed([b"block", b"envelope", b"", b"blob"]);
        let contents = BlockContents::parse(&buf).unwrap();
        assert_eq!(contents.block, b"block");
        assert_eq!(contents.envelope, b"envelope");
        assert_eq!(contents.kzg_proofs, b"");
        assert_eq!(contents.blobs, b"blob");

        let mut shifted = buf.clone();
        shifted[0] += 1;
        assert!(BlockContents::parse(&shifted).is_none());
        assert!(BlockContents::parse(&buf[..BlockContents::FIXED - 1]).is_none());
    }
}
