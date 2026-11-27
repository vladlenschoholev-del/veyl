#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet, VecDeque},
    io,
    str::FromStr,
    time::Duration,
};

use axum::{
    Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use getrandom::fill;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::{
    net::TcpListener,
    sync::Mutex,
    time::{Instant, interval},
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use veyl_crypto_core::relay_packet::{PROTOCOL_VERSION, RelayPacket};
use zeroize::Zeroizing;

const QUEUE_ID_SIZE: usize = 32;
const CAPABILITY_SIZE: usize = 32;
const QUEUE_CREDENTIALS_SIZE: usize = 1 + QUEUE_ID_SIZE + CAPABILITY_SIZE * 2;
const QUEUE_ACCESS_SIZE: usize = QUEUE_ID_SIZE + CAPABILITY_SIZE;
const QUEUE_ACCESS_REQUEST_SIZE: usize = 1 + QUEUE_ACCESS_SIZE;
const MESSAGE_HEADER_SIZE: usize = 3;
const ACK_HEADER_SIZE: usize = 1 + QUEUE_ACCESS_SIZE + 2;
const RECORD_ID_SIZE: usize = 16;
const MAX_BODY_SIZE: usize = 16_517;
const MAX_QUEUES: usize = 4096;
const MAX_QUEUE_RECORDS: usize = 128;
const MAX_BATCH_RECORDS: usize = 32;
const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_IDEMPOTENCY_ENTRIES: usize = 65_536;
const QUEUE_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MESSAGE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const RATE_WINDOW: Duration = Duration::from_secs(60);
const WRITE_LIMIT_PER_WINDOW: u32 = 60;
const READ_LIMIT_PER_WINDOW: u32 = 120;
const ACK_LIMIT_PER_WINDOW: u32 = 120;
const CLEANUP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
struct AppState {
    inner: std::sync::Arc<Mutex<RelayState>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(RelayState::default())),
        }
    }
}

#[derive(Default)]
struct RelayState {
    queues: HashMap<[u8; QUEUE_ID_SIZE], Queue>,
    stored_bytes: usize,
    idempotency_entries: usize,
}

struct Queue {
    write_capability: Zeroizing<[u8; CAPABILITY_SIZE]>,
    read_capability: Zeroizing<[u8; CAPABILITY_SIZE]>,
    records: VecDeque<QueueRecord>,
    created_at: Instant,
    write_rate: RateWindow,
    read_rate: RateWindow,
    ack_rate: RateWindow,
    idempotency: HashMap<[u8; RECORD_ID_SIZE], IdempotencyEntry>,
}

struct IdempotencyEntry {
    digest: [u8; 32],
    created_at: Instant,
}

struct QueueRecord {
    receipt: [u8; RECORD_ID_SIZE],
    encrypted_payload: Vec<u8>,
    created_at: Instant,
}

#[derive(Default)]
struct RateWindow {
    started_at: Option<Instant>,
    requests: u32,
}

impl RateWindow {
    fn allow(&mut self, now: Instant, limit: u32) -> bool {
        if self
            .started_at
            .is_none_or(|started_at| now.duration_since(started_at) >= RATE_WINDOW)
        {
            self.started_at = Some(now);
            self.requests = 0;
        }
        if self.requests >= limit {
            return false;
        }
        self.requests += 1;
        true
    }
}

impl RelayState {
    fn remove_expired(&mut self, now: Instant) {
        self.queues.retain(|_, queue| {
            if now.duration_since(queue.created_at) >= QUEUE_TTL {
                return false;
            }
            queue
                .records
                .retain(|record| now.duration_since(record.created_at) < MESSAGE_TTL);
            queue
                .idempotency
                .retain(|_, entry| now.duration_since(entry.created_at) < MESSAGE_TTL);
            true
        });
        self.stored_bytes = self
            .queues
            .values()
            .flat_map(|queue| &queue.records)
            .map(|record| record.encrypted_payload.len())
            .sum();
        self.idempotency_entries = self
            .queues
            .values()
            .map(|queue| queue.idempotency.len())
            .sum();
    }
}

pub fn router() -> Router {
    router_with_state_and_origins(AppState::new(), Vec::new())
}

fn router_with_state_and_origins(state: AppState, allowed_origins: Vec<HeaderValue>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/queues", post(create_queue))
        .route("/v1/queues/messages", post(write_message))
        .route("/v1/queues/read", post(read_messages))
        .route("/v1/queues/ack", post(ack_messages))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY_SIZE))
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed_origins))
                .allow_methods([Method::GET, Method::POST])
                .allow_headers([
                    header::CONTENT_TYPE,
                    HeaderName::from_static("idempotency-key"),
                ])
                .max_age(Duration::from_secs(600)),
        )
        .with_state(state)
}

fn configured_origins() -> io::Result<Vec<HeaderValue>> {
    let Ok(value) = std::env::var("ALLOWED_ORIGINS") else {
        return Ok(Vec::new());
    };
    parse_allowed_origins(&value)
}

fn parse_allowed_origins(value: &str) -> io::Result<Vec<HeaderValue>> {
    let mut origins = Vec::new();
    for origin in value
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
    {
        if origin == "*" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ALLOWED_ORIGINS must not contain a wildcard.",
            ));
        }
        let uri = Uri::from_str(origin).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ALLOWED_ORIGINS contains an invalid origin.",
            )
        })?;
        let scheme = uri.scheme_str().unwrap_or_default();
        let authority = uri
            .authority()
            .map(|value| value.as_str())
            .unwrap_or_default();
        if (scheme != "http" && scheme != "https")
            || authority.is_empty()
            || authority.contains('@')
            || uri.query().is_some()
            || format!("{scheme}://{authority}") != origin
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ALLOWED_ORIGINS entries must be exact http(s) origins without paths or credentials.",
            ));
        }
        origins.push(HeaderValue::from_str(origin).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ALLOWED_ORIGINS contains an invalid header value.",
            )
        })?);
    }
    Ok(origins)
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Starts the relay and a periodic in-memory TTL cleanup task.
pub async fn serve(listener: TcpListener) -> io::Result<()> {
    let state = AppState::new();
    let app = router_with_state_and_origins(state.clone(), configured_origins()?);
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut ticker = interval(CLEANUP_INTERVAL);
        loop {
            ticker.tick().await;
            cleanup_state
                .inner
                .lock()
                .await
                .remove_expired(Instant::now());
        }
    });
    axum::serve(listener, app).await.map_err(io::Error::other)
}

async fn create_queue(State(state): State<AppState>) -> Response {
    let mut queue_id = [0u8; QUEUE_ID_SIZE];
    let mut write_capability = Zeroizing::new([0u8; CAPABILITY_SIZE]);
    let mut read_capability = Zeroizing::new([0u8; CAPABILITY_SIZE]);
    if fill(&mut queue_id).is_err()
        || fill(&mut *write_capability).is_err()
        || fill(&mut *read_capability).is_err()
    {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let now = Instant::now();
    let mut relay = state.inner.lock().await;
    relay.remove_expired(now);
    if relay.queues.len() >= MAX_QUEUES || relay.queues.contains_key(&queue_id) {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    let mut response = Vec::with_capacity(QUEUE_CREDENTIALS_SIZE);
    response.push(PROTOCOL_VERSION);
    response.extend_from_slice(&queue_id);
    response.extend_from_slice(&write_capability[..]);
    response.extend_from_slice(&read_capability[..]);
    relay.queues.insert(
        queue_id,
        Queue {
            write_capability,
            read_capability,
            records: VecDeque::new(),
            created_at: now,
            write_rate: RateWindow::default(),
            read_rate: RateWindow::default(),
            ack_rate: RateWindow::default(),
            idempotency: HashMap::new(),
        },
    );
    binary_response(StatusCode::CREATED, response)
}

async fn write_message(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let packet = match RelayPacket::decode(&body) {
        Ok(packet) => packet,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let mut receipt = [0u8; RECORD_ID_SIZE];
    if fill(&mut receipt).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let idempotency_key = match headers.get("idempotency-key") {
        Some(value) => match parse_idempotency_key(value) {
            Some(key) => Some(key),
            None => return StatusCode::BAD_REQUEST.into_response(),
        },
        None => None,
    };
    let digest: [u8; 32] = Sha256::digest(&packet.encrypted_payload).into();

    let now = Instant::now();
    let mut relay = state.inner.lock().await;
    relay.remove_expired(now);
    let payload_size = packet.encrypted_payload.len();
    let Some(queue) = relay.queues.get_mut(&packet.queue_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !bool::from(queue.write_capability[..].ct_eq(&packet.write_capability[..])) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !queue.write_rate.allow(now, WRITE_LIMIT_PER_WINDOW) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if let Some(key) = idempotency_key {
        if let Some(previous) = queue.idempotency.get(&key) {
            return if bool::from(previous.digest.ct_eq(&digest)) {
                StatusCode::ACCEPTED.into_response()
            } else {
                StatusCode::CONFLICT.into_response()
            };
        }
        if relay.idempotency_entries >= MAX_IDEMPOTENCY_ENTRIES {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    }
    if queue.records.len() >= MAX_QUEUE_RECORDS {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if relay.stored_bytes.saturating_add(payload_size) > MAX_TOTAL_BYTES {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    queue.records.push_back(QueueRecord {
        receipt,
        encrypted_payload: packet.encrypted_payload,
        created_at: now,
    });
    if let Some(key) = idempotency_key {
        queue.idempotency.insert(
            key,
            IdempotencyEntry {
                digest,
                created_at: now,
            },
        );
        relay.idempotency_entries += 1;
    }
    relay.stored_bytes += payload_size;
    StatusCode::ACCEPTED.into_response()
}

fn parse_idempotency_key(value: &HeaderValue) -> Option<[u8; RECORD_ID_SIZE]> {
    let text = value.to_str().ok()?;
    if text.len() != RECORD_ID_SIZE * 2 {
        return None;
    }
    let mut key = [0u8; RECORD_ID_SIZE];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)? as u8;
        let low = (pair[1] as char).to_digit(16)? as u8;
        key[index] = (high << 4) | low;
    }
    Some(key)
}
async fn read_messages(State(state): State<AppState>, body: Bytes) -> Response {
    if body.len() != QUEUE_ACCESS_REQUEST_SIZE || body[0] != PROTOCOL_VERSION {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let queue_id: [u8; QUEUE_ID_SIZE] = match body[1..1 + QUEUE_ID_SIZE].try_into() {
        Ok(queue_id) => queue_id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let read_capability = &body[1 + QUEUE_ID_SIZE..];
    let now = Instant::now();
    let mut relay = state.inner.lock().await;
    relay.remove_expired(now);
    let Some(queue) = relay.queues.get_mut(&queue_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !bool::from(queue.read_capability[..].ct_eq(read_capability)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !queue.read_rate.allow(now, READ_LIMIT_PER_WINDOW) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let count = queue.records.len().min(MAX_BATCH_RECORDS);
    let mut response =
        Vec::with_capacity(MESSAGE_HEADER_SIZE + count * (RECORD_ID_SIZE + 4 + 16_517));
    response.push(PROTOCOL_VERSION);
    response.extend_from_slice(&(count as u16).to_be_bytes());
    for record in queue.records.iter().take(count) {
        response.extend_from_slice(&record.receipt);
        response.extend_from_slice(&(record.encrypted_payload.len() as u32).to_be_bytes());
        response.extend_from_slice(&record.encrypted_payload);
    }
    binary_response(StatusCode::OK, response)
}

async fn ack_messages(State(state): State<AppState>, body: Bytes) -> Response {
    if body.len() < ACK_HEADER_SIZE || body[0] != PROTOCOL_VERSION {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let queue_id: [u8; QUEUE_ID_SIZE] = match body[1..1 + QUEUE_ID_SIZE].try_into() {
        Ok(queue_id) => queue_id,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let read_capability = &body[1 + QUEUE_ID_SIZE..QUEUE_ACCESS_SIZE + 1];
    let count_bytes: [u8; 2] = match body[1 + QUEUE_ACCESS_SIZE..ACK_HEADER_SIZE].try_into() {
        Ok(count_bytes) => count_bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let count = u16::from_be_bytes(count_bytes) as usize;
    if count > MAX_BATCH_RECORDS || body.len() != ACK_HEADER_SIZE + count * RECORD_ID_SIZE {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let receipts: HashSet<[u8; RECORD_ID_SIZE]> = body[ACK_HEADER_SIZE..]
        .chunks_exact(RECORD_ID_SIZE)
        .filter_map(|bytes| bytes.try_into().ok())
        .collect();

    let now = Instant::now();
    let mut relay = state.inner.lock().await;
    relay.remove_expired(now);
    let Some(queue) = relay.queues.get_mut(&queue_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !bool::from(queue.read_capability[..].ct_eq(read_capability)) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if !queue.ack_rate.allow(now, ACK_LIMIT_PER_WINDOW) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let mut removed_bytes = 0usize;
    queue.records.retain(|record| {
        if receipts.contains(&record.receipt) {
            removed_bytes += record.encrypted_payload.len();
            false
        } else {
            true
        }
    });
    relay.stored_bytes = relay.stored_bytes.saturating_sub(removed_bytes);
    StatusCode::NO_CONTENT.into_response()
}

fn binary_response(status: StatusCode, body: Vec<u8>) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/octet-stream")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    use veyl_crypto_core::{
        handshake::{HybridOffer, authentication_string, respond},
        session::SessionState,
    };

    use super::*;

    async fn call(app: Router, path: &str, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        call_with_headers(app, path, body, &[]).await
    }

    async fn call_with_headers(
        app: Router,
        path: &str,
        body: Vec<u8>,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Vec<u8>) {
        let mut request =
            Request::post(path).header(header::CONTENT_TYPE, "application/octet-stream");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = app
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (status, bytes.to_vec())
    }

    #[tokio::test]
    async fn verified_hybrid_handshake_transfers_and_acknowledges_message() {
        let app = router();
        let (status, credentials) = call(app.clone(), "/v1/queues", Vec::new()).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(credentials.len(), QUEUE_CREDENTIALS_SIZE);
        assert_eq!(credentials[0], PROTOCOL_VERSION);
        let queue_id: [u8; QUEUE_ID_SIZE] = credentials[1..1 + QUEUE_ID_SIZE].try_into().unwrap();
        let write_capability: [u8; CAPABILITY_SIZE] = credentials
            [1 + QUEUE_ID_SIZE..1 + QUEUE_ID_SIZE + CAPABILITY_SIZE]
            .try_into()
            .unwrap();
        let read_capability: [u8; CAPABILITY_SIZE] = credentials
            [1 + QUEUE_ID_SIZE + CAPABILITY_SIZE..]
            .try_into()
            .unwrap();

        let offer = HybridOffer::create().unwrap();
        let offer_public = offer.public().clone();
        let (response, recipient_ratchet) = respond(&offer_public).unwrap();
        let sas = authentication_string(&offer_public, &response);
        let mut sender = SessionState::new_unverified(
            offer.finish(&response).unwrap(),
            &offer_public,
            &response,
        );
        let mut recipient =
            SessionState::new_unverified(recipient_ratchet, &offer_public, &response);
        assert_eq!(sas.len(), 12);
        sender.confirm_sas(&sas).unwrap();
        recipient.confirm_sas(&sas).unwrap();

        let encrypted = sender.encrypt(b"message transported by relay").unwrap();
        let payload = encrypted.to_relay_payload();
        let packet = RelayPacket {
            queue_id,
            write_capability: Zeroizing::new(write_capability),
            encrypted_payload: payload,
        };
        let (status, _) = call(app.clone(), "/v1/queues/messages", packet.encode().unwrap()).await;
        assert_eq!(status, StatusCode::ACCEPTED);

        let mut read_request = Vec::with_capacity(QUEUE_ACCESS_REQUEST_SIZE);
        read_request.push(PROTOCOL_VERSION);
        read_request.extend_from_slice(&queue_id);
        read_request.extend_from_slice(&read_capability);
        let (status, delivered) = call(app.clone(), "/v1/queues/read", read_request.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(delivered[0], PROTOCOL_VERSION);
        let count = u16::from_be_bytes(delivered[1..3].try_into().unwrap());
        assert_eq!(count, 1);
        let (status, repeated) = call(app.clone(), "/v1/queues/read", read_request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(repeated, delivered);
        let receipt: [u8; RECORD_ID_SIZE] = delivered[3..3 + RECORD_ID_SIZE].try_into().unwrap();
        let payload_len = u32::from_be_bytes(
            delivered[3 + RECORD_ID_SIZE..7 + RECORD_ID_SIZE]
                .try_into()
                .unwrap(),
        ) as usize;
        let encrypted_message = veyl_crypto_core::ratchet::RatchetMessage::from_relay_payload(
            &delivered[7 + RECORD_ID_SIZE..],
        )
        .unwrap();
        assert_eq!(
            recipient.decrypt(&encrypted_message).unwrap(),
            b"message transported by relay"
        );
        assert_eq!(
            payload_len,
            delivered.len() - MESSAGE_HEADER_SIZE - RECORD_ID_SIZE - 4
        );

        let mut ack = Vec::with_capacity(ACK_HEADER_SIZE + RECORD_ID_SIZE);
        ack.push(PROTOCOL_VERSION);
        ack.extend_from_slice(&queue_id);
        ack.extend_from_slice(&read_capability);
        ack.extend_from_slice(&1u16.to_be_bytes());
        ack.extend_from_slice(&receipt);
        let (status, _) = call(app.clone(), "/v1/queues/ack", ack.clone()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            call(app.clone(), "/v1/queues/ack", ack).await.0,
            StatusCode::NO_CONTENT
        );

        let mut read_request = Vec::new();
        read_request.push(PROTOCOL_VERSION);
        read_request.extend_from_slice(&queue_id);
        read_request.extend_from_slice(&read_capability);
        let (status, delivered) = call(app, "/v1/queues/read", read_request).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(u16::from_be_bytes(delivered[1..3].try_into().unwrap()), 0);
    }

    #[tokio::test]
    async fn rejects_invalid_capability_and_non_bucket_packets() {
        let app = router();
        let (_, credentials) = call(app.clone(), "/v1/queues", Vec::new()).await;
        let queue_id: [u8; QUEUE_ID_SIZE] = credentials[1..1 + QUEUE_ID_SIZE].try_into().unwrap();
        let bad_capability = [0x55; CAPABILITY_SIZE];
        let packet = RelayPacket {
            queue_id,
            write_capability: Zeroizing::new(bad_capability),
            encrypted_payload: vec![0; 1_092],
        };
        assert_eq!(
            call(app, "/v1/queues/messages", packet.encode().unwrap())
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );

        let mut malformed_record = Vec::with_capacity(QUEUE_ACCESS_SIZE + 1);
        malformed_record.push(PROTOCOL_VERSION);
        malformed_record.extend_from_slice(&queue_id);
        malformed_record.extend_from_slice(&bad_capability);
        malformed_record.push(0);
        assert_eq!(
            call(router(), "/v1/queues/messages", malformed_record)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn health_is_metadata_free_and_cors_is_exactly_allowlisted() {
        let app = router_with_state_and_origins(
            AppState::new(),
            vec![HeaderValue::from_static("https://client.example")],
        );
        let response = app
            .oneshot(
                Request::get("/health")
                    .header(header::ORIGIN, "https://client.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            response
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://client.example"
        );
        assert!(!response.headers().contains_key(header::SERVER));

        let app = router_with_state_and_origins(
            AppState::new(),
            vec![HeaderValue::from_static("https://client.example")],
        );
        let response = app
            .oneshot(
                Request::get("/health")
                    .header(header::ORIGIN, "https://attacker.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            !response
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
    }

    #[test]
    fn cors_origin_configuration_rejects_wildcards_paths_and_credentials() {
        assert_eq!(
            parse_allowed_origins("https://client.example,http://localhost:5173")
                .unwrap()
                .len(),
            2
        );
        assert!(parse_allowed_origins("*").is_err());
        assert!(parse_allowed_origins("https://client.example/path").is_err());
        assert!(parse_allowed_origins("https://user@client.example").is_err());
    }

    #[tokio::test]
    async fn repeated_outbox_write_is_idempotent_and_key_reuse_is_rejected() {
        let app = router();
        let (_, credentials) = call(app.clone(), "/v1/queues", Vec::new()).await;
        let queue_id: [u8; QUEUE_ID_SIZE] = credentials[1..1 + QUEUE_ID_SIZE].try_into().unwrap();
        let write_capability: [u8; CAPABILITY_SIZE] = credentials
            [1 + QUEUE_ID_SIZE..1 + QUEUE_ID_SIZE + CAPABILITY_SIZE]
            .try_into()
            .unwrap();
        let read_capability: [u8; CAPABILITY_SIZE] = credentials
            [1 + QUEUE_ID_SIZE + CAPABILITY_SIZE..]
            .try_into()
            .unwrap();
        let payload = vec![0x31; 40 + 12 + 1024 + 16];
        let key = "aabbccddeeff00112233445566778899";
        let packet = |payload: Vec<u8>| {
            RelayPacket {
                queue_id,
                write_capability: Zeroizing::new(write_capability),
                encrypted_payload: payload,
            }
            .encode()
            .unwrap()
        };
        assert_eq!(
            call_with_headers(
                app.clone(),
                "/v1/queues/messages",
                packet(payload.clone()),
                &[("idempotency-key", key)],
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call_with_headers(
                app.clone(),
                "/v1/queues/messages",
                packet(payload),
                &[("idempotency-key", key)],
            )
            .await
            .0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call_with_headers(
                app.clone(),
                "/v1/queues/messages",
                packet(vec![0x32; 40 + 12 + 1024 + 16]),
                &[("idempotency-key", key)],
            )
            .await
            .0,
            StatusCode::CONFLICT
        );
        let mut read = vec![PROTOCOL_VERSION];
        read.extend_from_slice(&queue_id);
        read.extend_from_slice(&read_capability);
        let (_, batch) = call(app, "/v1/queues/read", read).await;
        assert_eq!(u16::from_be_bytes(batch[1..3].try_into().unwrap()), 1);
    }
}
