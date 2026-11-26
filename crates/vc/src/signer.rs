use crate::{
    keys::ValidatorKey,
    signing::{SignAnswer, SignRequest},
};

/// Holds the keys the leanVM signer will sign with. Until then it refuses
/// every request, so each duty ends unsigned rather than waiting.
pub struct Signer {
    keys: Vec<ValidatorKey>,
}

impl Signer {
    pub fn new(keys: Vec<ValidatorKey>) -> Self {
        Self { keys }
    }

    pub fn answer(&self, request: &SignRequest) -> SignAnswer<'static> {
        if self.keys.binary_search_by_key(&request.pubkey, |key| key.pubkey).is_err() {
            let pubkey = hex::encode(request.pubkey);
            silver_log::error!(pubkey, purpose = ?request.purpose, "no key to sign with");
        } else {
            silver_log::warn!(
                slot = request.slot,
                purpose = ?request.purpose,
                "not signed: no leanVM signer yet"
            );
        }
        SignAnswer::Refused
    }
}
