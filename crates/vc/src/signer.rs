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

    pub fn answer(&self, request: &SignRequest) -> SignAnswer {
        let pubkey = hex::encode(request.pubkey);
        if self.keys.binary_search_by_key(&request.pubkey, |key| key.pubkey).is_err() {
            silver_log::error!(pubkey, purpose = ?request.purpose, "no key to sign with");
        } else {
            silver_log::warn!(pubkey, purpose = ?request.purpose, "not signed: no leanVM signer yet");
        }
        SignAnswer::Refused
    }
}
