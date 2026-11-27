#![forbid(unsafe_code)]

use subtle::ConstantTimeEq;
use veyl_crypto_core::{
    CryptoError,
    backup::{decrypt_backup as decrypt_backup_bytes, encrypt_backup as encrypt_backup_bytes},
    handshake::{HybridOffer, HybridOfferPublic, HybridResponse, authentication_string, respond},
    key_wrap::PinKeyWrap,
    media, padding,
    persistence::{open_local_record, seal_local_record},
    ratchet::RatchetMessage,
    session::{SessionState, VerificationStatus},
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProfileMode {
    Locked,
    Real,
    DuressPendingCleanup,
    Decoy,
}

#[wasm_bindgen]
pub struct WasmInitiator {
    offer: Option<HybridOffer>,
    public_offer: HybridOfferPublic,
}

#[wasm_bindgen]
impl WasmInitiator {
    #[wasm_bindgen(constructor)]
    pub fn create() -> std::result::Result<WasmInitiator, JsValue> {
        let offer = HybridOffer::create().map_err(to_js_error)?;
        let public_offer = offer.public().clone();
        Ok(Self {
            offer: Some(offer),
            public_offer,
        })
    }

    #[wasm_bindgen(js_name = publicBytes)]
    pub fn public_bytes(&self) -> Vec<u8> {
        encode_offer(&self.public_offer)
    }

    pub fn finish(&mut self, response_bytes: &[u8]) -> std::result::Result<WasmSession, JsValue> {
        let response = decode_response(response_bytes)?;
        let offer = self
            .offer
            .take()
            .ok_or_else(|| JsValue::from_str("Handshake offer already consumed."))?;
        let sas = authentication_string(&self.public_offer, &response);
        let ratchet = offer.finish(&response).map_err(to_js_error)?;
        Ok(WasmSession::new(
            SessionState::new_unverified(ratchet, &self.public_offer, &response),
            Some(sas),
        ))
    }
}

#[wasm_bindgen]
pub struct WasmResponder {
    response_bytes: Vec<u8>,
    session: Option<WasmSession>,
}

#[wasm_bindgen]
impl WasmResponder {
    #[wasm_bindgen(js_name = responseBytes)]
    pub fn response_bytes(&self) -> Vec<u8> {
        self.response_bytes.clone()
    }

    #[wasm_bindgen(js_name = takeSession)]
    pub fn take_session(&mut self) -> std::result::Result<WasmSession, JsValue> {
        self.session
            .take()
            .ok_or_else(|| JsValue::from_str("Responder session already taken."))
    }
}

#[wasm_bindgen]
pub fn create_responder(offer_bytes: &[u8]) -> std::result::Result<WasmResponder, JsValue> {
    let public_offer = decode_offer(offer_bytes)?;
    let (response, ratchet) = respond(&public_offer).map_err(to_js_error)?;
    let sas = authentication_string(&public_offer, &response);
    let session = SessionState::new_unverified(ratchet, &public_offer, &response);
    Ok(WasmResponder {
        response_bytes: encode_response(&response),
        session: Some(WasmSession::new(session, Some(sas))),
    })
}

#[wasm_bindgen]
pub struct WasmSession {
    session: SessionState,
    sas: Option<String>,
}

impl WasmSession {
    fn new(session: SessionState, sas: Option<String>) -> Self {
        Self { session, sas }
    }
}

#[wasm_bindgen]
impl WasmSession {
    pub fn sas(&self) -> Option<String> {
        self.session.sas().or_else(|| self.sas.clone())
    }

    #[wasm_bindgen(js_name = verificationStatus)]
    pub fn verification_status(&self) -> String {
        match self.session.verification_status() {
            VerificationStatus::Unverified => "UNVERIFIED".to_owned(),
            VerificationStatus::Verified => "VERIFIED".to_owned(),
        }
    }

    pub fn confirm_sas(&mut self, entered: &str) -> std::result::Result<(), JsValue> {
        self.session.confirm_sas(entered).map_err(to_js_error)?;
        self.sas = None;
        Ok(())
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
        let message = self.session.encrypt(plaintext).map_err(to_js_error)?;
        Ok(message.to_relay_payload())
    }

    pub fn decrypt(&mut self, relay_payload: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
        let message = RatchetMessage::from_relay_payload(relay_payload).map_err(to_js_error)?;
        self.session.decrypt(&message).map_err(to_js_error)
    }
}

#[wasm_bindgen]
pub struct WasmProfile {
    real_wrap: Option<PinKeyWrap>,
    decoy_wrap: PinKeyWrap,
    active_data_key: Option<Zeroizing<[u8; 32]>>,
    pending_decoy_key: Option<Zeroizing<[u8; 32]>>,
    mode: ProfileMode,
    decoy_only: bool,
}

#[wasm_bindgen]
impl WasmProfile {
    #[wasm_bindgen(constructor)]
    pub fn create(
        primary_pin: &str,
        duress_pin: &str,
    ) -> std::result::Result<WasmProfile, JsValue> {
        if primary_pin.len() < 8
            || duress_pin.len() < 8
            || bool::from(primary_pin.as_bytes().ct_eq(duress_pin.as_bytes()))
        {
            return Err(JsValue::from_str(
                "PINs must be at least 8 bytes and distinct.",
            ));
        }
        let real_key = random_key()?;
        let mut decoy_key = random_key()?;
        while bool::from(real_key.as_ref().ct_eq(decoy_key.as_ref())) {
            decoy_key.zeroize();
            decoy_key = random_key()?;
        }
        let real_wrap = PinKeyWrap::create(primary_pin, &real_key).map_err(to_js_error)?;
        let decoy_wrap = PinKeyWrap::create(duress_pin, &decoy_key).map_err(to_js_error)?;
        Ok(Self {
            real_wrap: Some(real_wrap),
            decoy_wrap,
            active_data_key: Some(real_key),
            pending_decoy_key: None,
            mode: ProfileMode::Real,
            decoy_only: false,
        })
    }

    #[wasm_bindgen(js_name = fromStoredWraps)]
    pub fn from_stored_wraps(
        real_wrap_bytes: &[u8],
        decoy_wrap_bytes: &[u8],
        persistent_state: &str,
    ) -> std::result::Result<WasmProfile, JsValue> {
        let real_wrap = if real_wrap_bytes.is_empty() {
            None
        } else {
            Some(PinKeyWrap::from_bytes(real_wrap_bytes).map_err(to_js_error)?)
        };
        let decoy_wrap = PinKeyWrap::from_bytes(decoy_wrap_bytes).map_err(to_js_error)?;
        match persistent_state {
            "NORMAL" if real_wrap.is_none() => {
                return Err(JsValue::from_str(
                    "Real key wrapper missing in NORMAL state.",
                ));
            }
            "ACTIVE" if real_wrap.is_some() => {
                return Err(JsValue::from_str(
                    "Real key wrapper remains after duress cleanup.",
                ));
            }
            "NORMAL" | "ACTIVE" => {}
            "DURESS_PENDING_CLEANUP" => {
                return Err(JsValue::from_str(
                    "Pending duress cleanup must be recovered before loading the vault.",
                ));
            }
            _ => return Err(JsValue::from_str("Unknown persistent profile state.")),
        }
        Ok(Self {
            real_wrap,
            decoy_wrap,
            active_data_key: None,
            pending_decoy_key: None,
            mode: ProfileMode::Locked,
            decoy_only: persistent_state == "ACTIVE",
        })
    }

    #[wasm_bindgen(js_name = realKeyWrap)]
    pub fn real_key_wrap(&self) -> Vec<u8> {
        self.real_wrap
            .as_ref()
            .map(PinKeyWrap::to_bytes)
            .unwrap_or_default()
    }

    #[wasm_bindgen(js_name = decoyKeyWrap)]
    pub fn decoy_key_wrap(&self) -> Vec<u8> {
        self.decoy_wrap.to_bytes()
    }

    #[wasm_bindgen(js_name = unlockWithPin)]
    pub fn unlock_with_pin(&mut self, pin: &str) -> std::result::Result<String, JsValue> {
        if self.mode != ProfileMode::Locked {
            return Err(JsValue::from_str("Profile vault is not locked."));
        }
        if self.decoy_only {
            let decoy_key = self
                .decoy_wrap
                .unwrap(pin)
                .map_err(to_js_error)?
                .ok_or_else(|| JsValue::from_str("Invalid PIN."))?;
            self.active_data_key = Some(decoy_key);
            self.mode = ProfileMode::Decoy;
            return Ok("DECOY".to_owned());
        }
        let real_key = self
            .real_wrap
            .as_ref()
            .map(|wrap| wrap.unwrap(pin))
            .transpose()
            .map_err(to_js_error)?
            .flatten();
        let decoy_key = self.decoy_wrap.unwrap(pin).map_err(to_js_error)?;
        if let Some(real_key) = real_key {
            self.active_data_key = Some(real_key);
            self.mode = ProfileMode::Real;
            return Ok("REAL".to_owned());
        }
        if let Some(decoy_key) = decoy_key {
            self.real_wrap = None;
            self.active_data_key = None;
            self.pending_decoy_key = Some(decoy_key);
            self.mode = ProfileMode::DuressPendingCleanup;
            return Ok("DURESS_PENDING_CLEANUP".to_owned());
        }
        Err(JsValue::from_str("Invalid PIN."))
    }

    #[wasm_bindgen(js_name = activateDecoyAfterCleanup)]
    pub fn activate_decoy_after_cleanup(&mut self) -> std::result::Result<(), JsValue> {
        if self.mode != ProfileMode::DuressPendingCleanup || self.real_wrap.is_some() {
            return Err(JsValue::from_str(
                "Decoy activation requires completed key-wrapper deletion.",
            ));
        }
        let decoy_key = self
            .pending_decoy_key
            .take()
            .ok_or_else(|| JsValue::from_str("Decoy key is not available."))?;
        self.active_data_key = Some(decoy_key);
        self.mode = ProfileMode::Decoy;
        self.decoy_only = true;
        Ok(())
    }

    pub fn profile_kind(&self) -> String {
        match self.mode {
            ProfileMode::Locked => "LOCKED",
            ProfileMode::Real => "REAL",
            ProfileMode::DuressPendingCleanup => "DURESS_PENDING_CLEANUP",
            ProfileMode::Decoy => "DECOY",
        }
        .to_owned()
    }

    #[wasm_bindgen(js_name = serializeSession)]
    pub fn serialize_session(
        &self,
        session: &WasmSession,
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let key = self.active_key()?;
        session
            .session
            .serialize_encrypted(key)
            .map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = restoreSession)]
    pub fn restore_session(
        &self,
        encrypted_snapshot: &[u8],
    ) -> std::result::Result<WasmSession, JsValue> {
        let key = self.active_key()?;
        let session =
            SessionState::restore_encrypted(encrypted_snapshot, key).map_err(to_js_error)?;
        let sas = session.sas();
        Ok(WasmSession::new(session, sas))
    }

    #[wasm_bindgen(js_name = sealLocalRecord)]
    pub fn seal_local_record(
        &self,
        record_key: &[u8],
        plaintext: &[u8],
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let key = fixed_key(record_key)?;
        seal_local_record(self.active_key()?, &key, plaintext).map_err(to_js_error)
    }

    #[wasm_bindgen(js_name = openLocalRecord)]
    pub fn open_local_record(
        &self,
        record_key: &[u8],
        encrypted_record: &[u8],
    ) -> std::result::Result<Vec<u8>, JsValue> {
        let key = fixed_key(record_key)?;
        open_local_record(self.active_key()?, &key, encrypted_record).map_err(to_js_error)
    }

    pub fn lock(&mut self) {
        self.active_data_key = None;
        self.pending_decoy_key = None;
        self.mode = ProfileMode::Locked;
    }
}

impl WasmProfile {
    fn active_key(&self) -> std::result::Result<&[u8; 32], JsValue> {
        self.active_data_key
            .as_deref()
            .ok_or_else(|| JsValue::from_str("Profile key is not active."))
    }
}

#[wasm_bindgen]
pub fn sanitize_image(input: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    media::strip_image_metadata(input).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn encrypt_backup(password: &str, plaintext: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    encrypt_backup_bytes(password, plaintext).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn decrypt_backup(password: &str, encoded: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    decrypt_backup_bytes(password, encoded).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn pad_payload(input: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    padding::pad(input).map_err(to_js_error)
}

#[wasm_bindgen]
pub fn unpad_payload(input: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    padding::unpad(input)
        .map(ToOwned::to_owned)
        .map_err(to_js_error)
}

fn random_key() -> std::result::Result<Zeroizing<[u8; 32]>, JsValue> {
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(key.as_mut())
        .map_err(|_| JsValue::from_str("Secure randomness unavailable."))?;
    Ok(key)
}

fn fixed_key(input: &[u8]) -> std::result::Result<[u8; 32], JsValue> {
    input
        .try_into()
        .map_err(|_| JsValue::from_str("Local record key must be 32 bytes."))
}

fn encode_offer(offer: &HybridOfferPublic) -> Vec<u8> {
    offer.to_bytes()
}

fn decode_offer(encoded: &[u8]) -> std::result::Result<HybridOfferPublic, JsValue> {
    HybridOfferPublic::from_bytes(encoded).map_err(to_js_error)
}

fn encode_response(response: &HybridResponse) -> Vec<u8> {
    response.to_bytes()
}

fn decode_response(encoded: &[u8]) -> std::result::Result<HybridResponse, JsValue> {
    HybridResponse::from_bytes(encoded).map_err(to_js_error)
}

fn to_js_error(error: CryptoError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_handshake_and_ratchet_round_trip() {
        let mut initiator = WasmInitiator::create().unwrap();
        let mut responder = create_responder(&initiator.public_bytes()).unwrap();
        let response = responder.response_bytes();
        let mut alice = initiator.finish(&response).unwrap();
        let mut bob = responder.take_session().unwrap();
        let sas = alice.sas().unwrap();
        assert_eq!(sas.len(), 12);
        assert_eq!(bob.sas().as_deref(), Some(sas.as_str()));
        assert_eq!(alice.verification_status(), "UNVERIFIED");
        alice.confirm_sas(&sas).unwrap();
        bob.confirm_sas(&sas).unwrap();
        let packet = alice.encrypt(b"wasm client").unwrap();
        assert_eq!(bob.decrypt(&packet).unwrap(), b"wasm client");
    }

    #[test]
    fn pin_vault_withholds_decoy_until_storage_cleanup_is_confirmed() {
        let mut profile = WasmProfile::create("primary-pin-42", "duress-pin-42").unwrap();
        let real = profile.real_key_wrap();
        let decoy = profile.decoy_key_wrap();
        let mut restored = WasmProfile::from_stored_wraps(&real, &decoy, "NORMAL").unwrap();
        assert_eq!(
            restored.unlock_with_pin("duress-pin-42").unwrap(),
            "DURESS_PENDING_CLEANUP"
        );
        assert_eq!(restored.profile_kind(), "DURESS_PENDING_CLEANUP");
        assert!(restored.activate_decoy_after_cleanup().is_ok());
        assert_eq!(restored.profile_kind(), "DECOY");
    }
}
