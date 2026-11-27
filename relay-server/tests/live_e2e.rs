use std::{io::Cursor, net::SocketAddr};

use axum::http::StatusCode;
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use veyl_crypto_core::{
    CryptoError,
    duress::{
        DeletionReceipt, KeyWrapStorage, PersistentDuressState, ProfileRuntime, RuntimeProfileState,
    },
    handshake::{HybridOffer, HybridOfferPublic, HybridResponse, authentication_string, respond},
    media, padding,
    ratchet::RatchetMessage,
    relay_packet::{PROTOCOL_VERSION, RelayPacket},
    session::{SessionState, VerificationStatus},
    vault::{PinVault, ProfileKind},
};
use zeroize::Zeroizing;

const QUEUE_ID_SIZE: usize = 32;
const CAPABILITY_SIZE: usize = 32;
const QUEUE_ACCESS_SIZE: usize = QUEUE_ID_SIZE + CAPABILITY_SIZE;
const RECORD_ID_SIZE: usize = 16;
const BATCH_HEADER_SIZE: usize = 3;
const INVITE_MAGIC: &[u8; 8] = b"USTOYI1\0";
const REPLY_MAGIC: &[u8; 8] = b"USTOYR1\0";

#[derive(Clone)]
struct Queue {
    id: [u8; QUEUE_ID_SIZE],
    write_capability: [u8; CAPABILITY_SIZE],
    read_capability: [u8; CAPABILITY_SIZE],
}

impl Queue {
    async fn create(address: SocketAddr) -> Self {
        let (status, credentials) = post(address, "/v1/queues", &[]).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(credentials.len(), 1 + QUEUE_ID_SIZE + 2 * CAPABILITY_SIZE);
        assert_eq!(credentials[0], PROTOCOL_VERSION);
        Self {
            id: credentials[1..33].try_into().unwrap(),
            write_capability: credentials[33..65].try_into().unwrap(),
            read_capability: credentials[65..97].try_into().unwrap(),
        }
    }

    fn invitation_bytes(&self, public_offer: &HybridOfferPublic) -> Vec<u8> {
        let offer = public_offer.to_bytes();
        let mut invitation =
            Vec::with_capacity(INVITE_MAGIC.len() + QUEUE_ACCESS_SIZE + offer.len());
        invitation.extend_from_slice(INVITE_MAGIC);
        invitation.extend_from_slice(&queue_access(self));
        invitation.extend_from_slice(&offer);
        invitation
    }

    fn write_access(&self) -> Vec<u8> {
        let mut access = Vec::with_capacity(QUEUE_ACCESS_SIZE);
        access.extend_from_slice(&self.id);
        access.extend_from_slice(&self.write_capability);
        access
    }
}

fn queue_access(queue: &Queue) -> Vec<u8> {
    queue.write_access()
}

async fn post(address: SocketAddr, path: &str, body: &[u8]) -> (StatusCode, Vec<u8>) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    let header_end = loop {
        assert_ne!(
            stream.read(&mut byte).await.unwrap(),
            0,
            "relay closed before returning an HTTP response for {path}"
        );
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            break response.len() - 4;
        }
    };
    let headers = std::str::from_utf8(&response[..header_end]).unwrap();
    let status_code = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap();
    let body_length = headers
        .lines()
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut response_body = vec![0u8; body_length];
    stream.read_exact(&mut response_body).await.unwrap();
    (StatusCode::from_u16(status_code).unwrap(), response_body)
}

async fn relay_payload(address: SocketAddr, queue: &Queue, encrypted_payload: Vec<u8>) -> Vec<u8> {
    let packet = RelayPacket {
        queue_id: queue.id,
        write_capability: Zeroizing::new(queue.write_capability),
        encrypted_payload,
    };
    let (status, _) = post(address, "/v1/queues/messages", &packet.encode().unwrap()).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let mut read_request = Vec::with_capacity(1 + QUEUE_ACCESS_SIZE);
    read_request.push(PROTOCOL_VERSION);
    read_request.extend_from_slice(&queue.id);
    read_request.extend_from_slice(&queue.read_capability);
    let (status, batch) = post(address, "/v1/queues/read", &read_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(batch[0], PROTOCOL_VERSION);
    assert_eq!(
        u16::from_be_bytes(batch[1..3].try_into().unwrap()),
        1,
        "the queue should contain one packet"
    );

    let receipt: [u8; RECORD_ID_SIZE] = batch
        [BATCH_HEADER_SIZE..BATCH_HEADER_SIZE + RECORD_ID_SIZE]
        .try_into()
        .unwrap();
    let length_offset = BATCH_HEADER_SIZE + RECORD_ID_SIZE;
    let payload_length =
        u32::from_be_bytes(batch[length_offset..length_offset + 4].try_into().unwrap()) as usize;
    let payload_offset = length_offset + 4;
    assert_eq!(payload_offset + payload_length, batch.len());
    let payload = batch[payload_offset..].to_vec();

    let mut ack = Vec::with_capacity(1 + QUEUE_ACCESS_SIZE + 2 + RECORD_ID_SIZE);
    ack.push(PROTOCOL_VERSION);
    ack.extend_from_slice(&queue.id);
    ack.extend_from_slice(&queue.read_capability);
    ack.extend_from_slice(&1u16.to_be_bytes());
    ack.extend_from_slice(&receipt);
    assert_eq!(
        post(address, "/v1/queues/ack", &ack).await.0,
        StatusCode::NO_CONTENT
    );
    payload
}

#[derive(Default)]
struct TestStorage {
    state: PersistentDuressState,
    real_wrap_present: bool,
}

impl KeyWrapStorage for TestStorage {
    type Error = &'static str;

    fn duress_state(&mut self) -> Result<PersistentDuressState, Self::Error> {
        Ok(self.state)
    }

    fn mark_duress_pending_cleanup(&mut self) -> Result<(), Self::Error> {
        self.state = PersistentDuressState::PendingCleanup;
        Ok(())
    }

    fn delete_real_key_wrap(&mut self) -> Result<DeletionReceipt, Self::Error> {
        if self.state != PersistentDuressState::PendingCleanup {
            return Err("duress cleanup was not marked pending");
        }
        self.real_wrap_present = false;
        Ok(DeletionReceipt::confirmed())
    }

    fn mark_duress_active(&mut self) -> Result<(), Self::Error> {
        if self.real_wrap_present {
            return Err("real key wrapper still exists");
        }
        self.state = PersistentDuressState::Active;
        Ok(())
    }
}

#[tokio::test]
async fn two_clients_complete_handshake_relay_media_snapshot_and_duress_over_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay = tokio::spawn(async move { veyl_relay_server::serve(listener).await.unwrap() });

    let alice_queue = Queue::create(address).await;
    let bob_queue = Queue::create(address).await;
    let alice_offer = HybridOffer::create().unwrap();
    let invitation = alice_queue.invitation_bytes(alice_offer.public());
    assert_eq!(&invitation[..INVITE_MAGIC.len()], INVITE_MAGIC);
    let invitation_offer_offset = INVITE_MAGIC.len() + QUEUE_ACCESS_SIZE;
    let imported_offer =
        HybridOfferPublic::from_bytes(&invitation[invitation_offer_offset..]).unwrap();
    let (response, bob_ratchet) = respond(&imported_offer).unwrap();
    let response = HybridResponse::from_bytes(&response.to_bytes()).unwrap();
    let mut reply =
        Vec::with_capacity(REPLY_MAGIC.len() + 2 * QUEUE_ACCESS_SIZE + response.to_bytes().len());
    reply.extend_from_slice(REPLY_MAGIC);
    reply.extend_from_slice(&alice_queue.write_access());
    reply.extend_from_slice(&bob_queue.write_access());
    reply.extend_from_slice(&response.to_bytes());
    assert_eq!(&reply[..REPLY_MAGIC.len()], REPLY_MAGIC);
    let invited_queue_access = alice_queue.write_access();
    assert_eq!(
        &reply[REPLY_MAGIC.len()..REPLY_MAGIC.len() + QUEUE_ACCESS_SIZE],
        invited_queue_access.as_slice()
    );
    let response_offset = REPLY_MAGIC.len() + 2 * QUEUE_ACCESS_SIZE;
    let response = HybridResponse::from_bytes(&reply[response_offset..]).unwrap();
    let sas = authentication_string(&imported_offer, &response);
    let mut alice = SessionState::new_unverified(
        alice_offer.finish(&response).unwrap(),
        &imported_offer,
        &response,
    );
    let mut bob = SessionState::new_unverified(bob_ratchet, &imported_offer, &response);
    assert_eq!(sas.len(), 12);
    assert_eq!(alice.verification_status(), VerificationStatus::Unverified);
    assert_eq!(bob.verification_status(), VerificationStatus::Unverified);
    alice.confirm_sas(&sas).unwrap();
    bob.confirm_sas(&sas).unwrap();
    assert_eq!(alice.verification_status(), VerificationStatus::Verified);
    assert_eq!(bob.verification_status(), VerificationStatus::Verified);

    let text = padding::pad(b"live TCP relay test").unwrap();
    let encrypted_text = alice.encrypt(&text).unwrap().to_relay_payload();
    let relayed_text = relay_payload(address, &bob_queue, encrypted_text).await;
    let decrypted_text = bob
        .decrypt(&RatchetMessage::from_relay_payload(&relayed_text).unwrap())
        .unwrap();
    assert_eq!(
        padding::unpad(&decrypted_text).unwrap(),
        b"live TCP relay test"
    );

    let image = DynamicImage::ImageRgb8(ImageBuffer::from_pixel(2, 2, Rgb([12, 34, 56])));
    let mut jpeg = Cursor::new(Vec::new());
    image.write_to(&mut jpeg, ImageFormat::Jpeg).unwrap();
    let sanitized_jpeg = media::strip_image_metadata(jpeg.get_ref()).unwrap();
    assert!(matches!(
        media::strip_image_metadata(b"unsupported audio/document"),
        Err(CryptoError::UnsupportedMedia)
    ));

    let profile_data_key = [0x71; 32];
    let snapshot = alice.serialize_encrypted(&profile_data_key).unwrap();
    let mut alice = SessionState::restore_encrypted(&snapshot, &profile_data_key).unwrap();
    let encrypted_image = bob
        .encrypt(&padding::pad(&sanitized_jpeg).unwrap())
        .unwrap()
        .to_relay_payload();
    let relayed_image = relay_payload(address, &alice_queue, encrypted_image).await;
    let decrypted_image = alice
        .decrypt(&RatchetMessage::from_relay_payload(&relayed_image).unwrap())
        .unwrap();
    assert_eq!(padding::unpad(&decrypted_image).unwrap(), sanitized_jpeg);

    let continued = alice
        .encrypt(&padding::pad(b"restored ratchet continued").unwrap())
        .unwrap();
    let relayed_continued = relay_payload(address, &bob_queue, continued.to_relay_payload()).await;
    let decrypted_continued = bob
        .decrypt(&RatchetMessage::from_relay_payload(&relayed_continued).unwrap())
        .unwrap();
    assert_eq!(
        padding::unpad(&decrypted_continued).unwrap(),
        b"restored ratchet continued"
    );

    let real_data_key = [0x31; 32];
    let decoy_data_key = [0x52; 32];
    let mut vault = PinVault::create(
        "primary-1842",
        "duress-7319",
        &real_data_key,
        &decoy_data_key,
    )
    .unwrap();
    let mut runtime = ProfileRuntime::with_real_profile(real_data_key);
    let mut storage = TestStorage {
        state: PersistentDuressState::Normal,
        real_wrap_present: true,
    };
    assert_eq!(
        vault
            .unlock_with_storage("duress-7319", &mut runtime, &mut storage)
            .unwrap(),
        ProfileKind::Decoy
    );
    assert_eq!(runtime.state(), RuntimeProfileState::Decoy);
    assert!(!runtime.has_real_material());
    assert!(!storage.real_wrap_present);
    assert_eq!(storage.state, PersistentDuressState::Active);

    relay.abort();
}
