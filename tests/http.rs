#![cfg(all(feature = "http", not(target_arch = "wasm32")))]
mod support;
use csrn::{Assurance, Error, feed::Config, http::Http};
use std::sync::Arc;
use support::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{self, pki_types::PrivatePkcs8KeyDer},
};
fn config() -> Config {
    Config {
        refresh_seconds: 40,
        poll_seconds: 2,
        request_seconds: 26,
        initial_backoff_seconds: 2,
        maximum_backoff_seconds: 16,
        retry_entropy: 0,
        maximum_staleness_seconds: 60,
    }
}
async fn server(reply: Vec<u8>) -> (String, Vec<u8>, tokio::task::JoinHandle<String>) {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let der = cert.der().clone();
    let provider = rustls::crypto::ring::default_provider();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![der.clone()],
            PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        let (io, _) = listener.accept().await.unwrap();
        let mut tls = TlsAcceptor::from(Arc::new(config))
            .accept(io)
            .await
            .unwrap();
        let mut bytes = Vec::new();
        let mut buf = [0; 4096];
        loop {
            let n = tls.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            bytes.extend_from_slice(&buf[..n]);
            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]).to_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|s| s.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        tls.write_all(&reply).await.unwrap();
        tls.shutdown().await.unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (origin, der.to_vec(), task)
}
#[tokio::test]
async fn real_https_fetch_bootstraps_without_member_headers_or_redirects() {
    let mut s = signer();
    let content = bytes(&feed(&mut s, 10, 1));
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    )
    .into_bytes();
    reply.extend_from_slice(&content);
    let (origin, root, server) = server(reply).await;
    let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
    let mut assurance = Assurance::new(configuration(&origin, "alpha"), config()).unwrap();
    let request = assurance.start(NOW).unwrap();
    let received = http.execute(request, NOW).await.unwrap();
    assurance
        .on_feed(request.id(), received.bytes(), NOW)
        .unwrap();
    assert_eq!(assurance.current(NOW).unwrap().revision(), 10);
    let trace = server.await.unwrap().to_lowercase();
    assert!(trace.starts_with("post /v1/trust_feed http/1.1"));
    assert!(trace.contains("user-agent: community-trust-client/1.0"));
    assert!(trace.contains("cache-control: no-cache, no-store"));
    assert!(trace.contains("pragma: no-cache"));
    assert!(!trace.contains("authorization:"));
    assert!(!trace.contains("cookie:"));
    assert!(!trace.contains("referer:"));
    assert!(trace.ends_with("{}"));
}
#[tokio::test]
async fn redirect_and_oversize_responses_are_refused() {
    for reply in [b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://127.0.0.1:9/\r\nContent-Length: 0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n".to_vec()] {
        let (origin,root,server)=server(reply).await;
        let http=Http::with_roots(&configuration(&origin,"alpha"),&[root]).unwrap();
        let mut a=Assurance::new(configuration(&origin,"alpha"),config()).unwrap();let request=a.start(NOW).unwrap();
        assert!(matches!(http.execute(request,NOW).await,Err(Error::Response)));
        server.await.unwrap();
    }
    assert!(Http::new(&configuration("http://localhost", "alpha")).is_err());
    assert!(Http::new(&configuration("https://user@localhost", "alpha")).is_err());
}

#[tokio::test]
async fn chunked_announcements_enforce_the_bound_without_a_length_header() {
    let body = vec![b' '; 2048];
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        body.len()
    )
    .into_bytes();
    reply.extend_from_slice(&body);
    reply.extend_from_slice(b"\r\n0\r\n\r\n");
    let (origin, root, server) = server(reply).await;
    let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
    let mut a = Assurance::new(configuration(&origin, "alpha"), config()).unwrap();
    let initial = a.start(NOW).unwrap();
    let mut s = signer();
    let wire = bytes(&feed(&mut s, 10, 1));
    a.on_feed(initial.id(), &wire, NOW).unwrap();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    assert!(matches!(
        http.execute(poll, NOW + 2).await,
        Err(Error::Response)
    ));
    assert!(server.await.unwrap().starts_with("POST /v1/trust_changes "));
}

#[tokio::test]
async fn malformed_feeds_and_late_requests_are_refused() {
    for content in [b"{}".to_vec(), br#"{"revision":1,"key_ring":[]}"#.to_vec()] {
        let mut reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            content.len()
        )
        .into_bytes();
        reply.extend_from_slice(&content);
        let (origin, root, server) = server(reply).await;
        let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
        let mut follower = csrn::feed::Follower::new(config()).unwrap();
        let request = follower.start(NOW).unwrap();
        assert!(matches!(
            http.execute(request, request.deadline()).await,
            Err(Error::Timeout)
        ));
        let response = http.execute(request, NOW).await.unwrap();
        let mut charter = csrn::cchr::Charter::new(configuration(&origin, "alpha")).unwrap();
        assert!(charter.install(response.bytes(), NOW).is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn announcement_response_is_only_a_hint() {
    let content = br#"{"revision":10,"policy_epoch":1,"changed":false}"#;
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    )
    .into_bytes();
    reply.extend_from_slice(content);
    let (origin, root, server) = server(reply).await;
    let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
    let mut signer = signer();
    let wire = bytes(&feed(&mut signer, 10, 1));
    let mut a = Assurance::new(configuration(&origin, "alpha"), config()).unwrap();
    let initial = a.start(NOW).unwrap();
    a.on_feed(initial.id(), &wire, NOW).unwrap();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    let received = http.execute(poll, NOW + 2).await.unwrap();
    a.on_announcement(poll.id(), received.bytes(), NOW + 2)
        .unwrap();
    assert_eq!(a.current(NOW + 2).unwrap().revision(), 10);
    server.await.unwrap();
}

#[tokio::test]
async fn real_connection_and_truncated_body_failures_are_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    drop(listener);
    let http = Http::new(&configuration(&origin, "alpha")).unwrap();
    let mut follower = csrn::feed::Follower::new(config()).unwrap();
    let request = follower.start(NOW).unwrap();
    assert!(matches!(
        http.execute(request, NOW).await,
        Err(Error::Network)
    ));

    let (origin, root, server) = server(
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\npartial".to_vec(),
    )
    .await;
    let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
    assert!(matches!(
        http.execute(request, NOW).await,
        Err(Error::Network)
    ));
    server.await.unwrap();
}

#[test]
fn malformed_operator_certificate_is_rejected_by_the_real_tls_builder() {
    assert!(matches!(
        Http::with_roots(&configuration("https://localhost", "alpha"), &[vec![]]),
        Err(Error::Network)
    ));
}

#[tokio::test]
async fn real_tls_requires_json_media_type_even_for_a_success_response() {
    for content_type in [
        None,
        Some("text/html"),
        Some("application/jsonish"),
        Some("APPLICATION/JSON; charset=utf-8"),
    ] {
        let header = content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        let reply = format!(
            "HTTP/1.1 200 OK\r\n{header}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        )
        .into_bytes();
        let (origin, root, server) = server(reply).await;
        let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
        let request = csrn::feed::Follower::new(config())
            .unwrap()
            .start(NOW)
            .unwrap();
        let response = http.execute(request, NOW).await;
        if content_type == Some("APPLICATION/JSON; charset=utf-8") {
            assert_eq!(response.unwrap().bytes(), b"{}");
        } else {
            assert!(matches!(response, Err(Error::Response)));
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn valid_tls_does_not_authorize_a_forged_publishing_ring() {
    let mut attacker = csgn::Signer::new(
        "alpha",
        csgn::SecretKey::from_seed(&mut [99; 32]),
        NOW - 1,
        1000,
    )
    .unwrap();
    let content = bytes(&feed(&mut attacker, 10, 1));
    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        content.len()
    ).into_bytes();
    reply.extend_from_slice(&content);
    let (origin, root, server) = server(reply).await;
    let http = Http::with_roots(&configuration(&origin, "alpha"), &[root]).unwrap();
    let mut assurance = Assurance::new(configuration(&origin, "alpha"), config()).unwrap();
    let request = assurance.start(NOW).unwrap();
    let received = http.execute(request, NOW).await.unwrap();
    assert_eq!(
        assurance.on_feed(request.id(), received.bytes(), NOW),
        Err(Error::Trust(csrn::cchr::Error::Unauthenticated))
    );
    assert!(assurance.current(NOW).is_err());
    server.await.unwrap();
}
