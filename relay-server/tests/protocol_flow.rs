use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use http_body_util::BodyExt;
use tower::ServiceExt;
use veyl_crypto_core::{
    handshake::{HybridOffer, authentication_string, respond},
    ratchet::RatchetMessage,
    relay_packet::{PROTOCOL_VERSION, RelayPacket},
    session::SessionState,
};
use zeroize::Zeroizing;

const QUEUE_ID_SIZE: usize = 32;
const CAPABILITY_SIZE: usize = 32;
const QUEUE_CREDENTIALS_SIZE: usize = 97;
const READ_REQUEST_SIZE: usize = 65;
const ACK_HEADER_SIZE: usize = 67;
const RECEIPT_SIZE: usize = 16;

async fn request(app: Router, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let response = app
        .oneshot(
            Request::post(path)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, bytes.to_vec())
}

#[tokio::test]
async fn sas_verified_padded_message_round_trips_through_relay() {
    let app = veyl_relay_server::router();
    let (status, credentials) = request(app.clone(), "/v1/queues", Vec::new()).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(credentials.len(), QUEUE_CREDENTIALS_SIZE);
    assert_eq!(credentials[0], PROTOCOL_VERSION);

    let queue_id: [u8; QUEUE_ID_SIZE] = credentials[1..33].try_into().unwrap();
    let write_capability: [u8; CAPABILITY_SIZE] = credentials[33..65].try_into().unwrap();
    let read_capability: [u8; CAPABILITY_SIZE] = credentials[65..97].try_into().unwrap();

    let offer = HybridOffer::create().unwrap();
    let public_offer = offer.public().clone();
    let (response, recipient_ratchet) = respond(&public_offer).unwrap();
    let sas = authentication_string(&public_offer, &response);
    assert_eq!(sas.len(), 12);

    let mut sender =
        SessionState::new_unverified(offer.finish(&response).unwrap(), &public_offer, &response);
    let mut recipient = SessionState::new_unverified(recipient_ratchet, &public_offer, &response);
    sender.confirm_sas(&sas).unwrap();
    recipient.confirm_sas(&sas).unwrap();

    let message = sender.encrypt(b"end-to-end relay integration").unwrap();
    let packet = RelayPacket {
        queue_id,
        write_capability: Zeroizing::new(write_capability),
        encrypted_payload: message.to_relay_payload(),
    };
    let (status, _) = request(app.clone(), "/v1/queues/messages", packet.encode().unwrap()).await;
    assert_eq!(status, StatusCode::ACCEPTED);

    let mut read_request = Vec::with_capacity(READ_REQUEST_SIZE);
    read_request.push(PROTOCOL_VERSION);
    read_request.extend_from_slice(&queue_id);
    read_request.extend_from_slice(&read_capability);
    let (status, batch) = request(app.clone(), "/v1/queues/read", read_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(batch[0], PROTOCOL_VERSION);
    assert_eq!(u16::from_be_bytes(batch[1..3].try_into().unwrap()), 1);
    let receipt: [u8; RECEIPT_SIZE] = batch[3..19].try_into().unwrap();
    let payload_length = u32::from_be_bytes(batch[19..23].try_into().unwrap()) as usize;
    let relayed_message = RatchetMessage::from_relay_payload(&batch[23..]).unwrap();
    assert_eq!(
        recipient.decrypt(&relayed_message).unwrap(),
        b"end-to-end relay integration"
    );
    assert_eq!(payload_length, batch.len() - 23);

    let mut ack = Vec::with_capacity(ACK_HEADER_SIZE + RECEIPT_SIZE);
    ack.push(PROTOCOL_VERSION);
    ack.extend_from_slice(&queue_id);
    ack.extend_from_slice(&read_capability);
    ack.extend_from_slice(&1u16.to_be_bytes());
    ack.extend_from_slice(&receipt);
    assert_eq!(
        request(app.clone(), "/v1/queues/ack", ack).await.0,
        StatusCode::NO_CONTENT
    );

    let mut read_request = Vec::with_capacity(READ_REQUEST_SIZE);
    read_request.push(PROTOCOL_VERSION);
    read_request.extend_from_slice(&queue_id);
    read_request.extend_from_slice(&read_capability);
    let (status, empty_batch) = request(app, "/v1/queues/read", read_request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(u16::from_be_bytes(empty_batch[1..3].try_into().unwrap()), 0);
}
