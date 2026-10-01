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
    let http = Http::with_roots(&origin, "alpha", &[root]).unwrap();
    let mut assurance = Assurance::new(&origin, "alpha", config()).unwrap();
    let request = assurance.start(NOW).unwrap();
    let received = http.execute(request, NOW).await.unwrap();
    let authority = received.authority(NOW, 60).unwrap();
    assurance
        .on_feed(request.id(), received.bytes(), &authority, NOW)
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
        let http=Http::with_roots(&origin,"alpha",&[root]).unwrap();
        let mut a=Assurance::new(&origin,"alpha",config()).unwrap();let request=a.start(NOW).unwrap();
        assert!(matches!(http.execute(request,NOW).await,Err(Error::Response)));
        server.await.unwrap();
    }
    assert!(Http::new("http://localhost", "alpha").is_err());
    assert!(Http::new("https://user@localhost", "alpha").is_err());
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
    let http = Http::with_roots(&origin, "alpha", &[root]).unwrap();
    let mut a = Assurance::new(&origin, "alpha", config()).unwrap();
    let initial = a.start(NOW).unwrap();
    let mut s = signer();
    let wire = bytes(&feed(&mut s, 10, 1));
    let trusted = csrn::cchr::AuthenticatedOrigin::from_authenticated_response(
        &origin,
        "alpha",
        &s.key_ring().to_cbor(),
        1,
        NOW,
        NOW + 60,
    )
    .unwrap();
    a.on_feed(initial.id(), &wire, &trusted, NOW).unwrap();
    let poll = a.next(NOW + 2).unwrap().unwrap();
    assert!(matches!(
        http.execute(poll, NOW + 2).await,
        Err(Error::Response)
    ));
    assert!(server.await.unwrap().starts_with("POST /v1/trust_changes "));
}
