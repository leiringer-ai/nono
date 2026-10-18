//! Fabricated upstream credentials only; no system keyring or provider account.
#![allow(clippy::unwrap_used)]
use base64::Engine;
use nono_proxy::{
    ProxyConfig,
    config::{ExternalProxyAuth, ExternalProxyConfig},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Duration, timeout},
};

async fn headers(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), async {
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
            assert!(bytes.len() < 16384);
        }
    })
    .await
    .unwrap();
    String::from_utf8(bytes).unwrap()
}
fn configuration(address: String, file: &std::path::Path) -> ProxyConfig {
    ProxyConfig {
        allowed_hosts: vec!["127.0.0.1".into()],
        external_proxy: Some(ExternalProxyConfig {
            address,
            auth: Some(ExternalProxyAuth {
                scheme: "basic".into(),
                keyring_account: format!("file://{}", file.display()),
            }),
            bypass_hosts: vec![],
        }),
        ..Default::default()
    }
}
#[tokio::test]
async fn configured_upstream_auth_replaces_child_proxy_auth_for_connect_and_http() {
    for plain_http in [false, true] {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "upstream:fixture-password").unwrap();
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = upstream.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let connect = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let request = headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
            (connect, request)
        });
        let handle = nono_proxy::start(configuration(address.to_string(), file.path()))
            .await
            .unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", handle.port))
            .await
            .unwrap();
        if !plain_http {
            client.write_all(format!("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nProxy-Authorization: Bearer {}\r\n\r\n", &*handle.token).as_bytes()).await.unwrap();
            assert!(headers(&mut client).await.contains("200"));
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                .await
                .unwrap();
        } else {
            client.write_all(format!("GET http://127.0.0.1/ HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: Bearer {}\r\nConnection: close\r\n\r\n", &*handle.token).as_bytes()).await.unwrap();
        }
        assert!(headers(&mut client).await.contains("200"));
        let (connect, request) = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        let expected =
            base64::engine::general_purpose::STANDARD.encode("upstream:fixture-password");
        assert!(connect.contains(&format!("Proxy-Authorization: Basic {expected}\r\n")));
        assert!(!connect.contains(&*handle.token));
        assert!(!request.to_lowercase().contains("proxy-authorization"));
        for (_, value) in handle.env_vars() {
            assert!(!value.contains(&expected));
        }
        handle.shutdown();
    }
}
#[tokio::test]
async fn bypass_does_not_send_upstream_credentials_to_destination() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), "upstream:fixture-password").unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = destination.local_addr().unwrap().port();
    let mut config = configuration(unused.local_addr().unwrap().to_string(), file.path());
    config.external_proxy.as_mut().unwrap().bypass_hosts = vec!["127.0.0.1".into()];
    let task = tokio::spawn(async move {
        let (mut stream, _) = destination.accept().await.unwrap();
        let request = headers(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        request
    });
    let handle = nono_proxy::start(config).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", handle.port))
        .await
        .unwrap();
    client.write_all(format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: Bearer {}\r\n\r\n", &*handle.token).as_bytes()).await.unwrap();
    assert!(headers(&mut client).await.contains("200"));
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        .await
        .unwrap();
    assert!(headers(&mut client).await.contains("200"));
    let request = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(!request.to_lowercase().contains("proxy-authorization"));
    assert!(
        timeout(Duration::from_millis(50), unused.accept())
            .await
            .is_err()
    );
    handle.shutdown();
}
