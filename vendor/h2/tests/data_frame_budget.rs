//! Wire-level regressions adapted from upstream security-fix commit 193833e.

use bytes::Bytes;
use h2::{client, Reason};
use http::Request;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::{timeout, Duration};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn encode_frame(typ: u8, flags: u8, id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = vec![(len >> 16) as u8, (len >> 8) as u8, len as u8, typ, flags];
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn write_frame(io: &mut DuplexStream, typ: u8, flags: u8, id: u32, payload: &[u8]) {
    io.write_all(&encode_frame(typ, flags, id, payload))
        .await
        .unwrap();
}

async fn read_frame(io: &mut DuplexStream) -> (u8, u8, Vec<u8>) {
    let mut header = [0; 9];
    io.read_exact(&mut header).await.unwrap();
    let len = ((header[0] as usize) << 16) | ((header[1] as usize) << 8) | header[2] as usize;
    let mut payload = vec![0; len];
    io.read_exact(&mut payload).await.unwrap();
    (header[3], header[4], payload)
}

async fn respond(peer: &mut DuplexStream) {
    let mut preface = [0; 24];
    peer.read_exact(&mut preface).await.unwrap();
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    write_frame(peer, 4, 0, 0, &[]).await; // SETTINGS
    loop {
        let (typ, flags, _) = read_frame(peer).await;
        if typ == 4 && flags & 1 == 0 {
            write_frame(peer, 4, 1, 0, &[]).await; // SETTINGS ACK
        }
        if typ == 1 {
            break;
        }
    }
    // HPACK indexed :status = 200, END_HEADERS but not END_STREAM.
    write_frame(peer, 1, 4, 1, &[0x88]).await;
}

async fn assert_excess_frames_close_connection(frames: Vec<(u8, Vec<u8>)>) {
    let (io, mut peer) = tokio::io::duplex(64 * 1024);
    let malicious_peer = tokio::spawn(async move {
        respond(&mut peer).await;
        let mut batch = Vec::new();
        for (flags, payload) in frames {
            batch.extend_from_slice(&encode_frame(0, flags, 1, &payload));
        }
        // Queue the attack before reading GOAWAY. The peer must not keep writing after the
        // connection has correctly closed partway through the small-frame attack.
        peer.write_all(&batch).await.unwrap();
        loop {
            let (typ, _, payload) = read_frame(&mut peer).await;
            if typ == 7 {
                assert_eq!(&payload[4..8], &11_u32.to_be_bytes());
                assert_eq!(&payload[8..], b"too_many_data_frames");
                break;
            }
        }
    });
    let (mut client, connection) = client::handshake(io).await.unwrap();
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    let response = client.send_request(request, true).unwrap().0.await.unwrap();
    // Keep the body alive and undrained, reproducing the advisory's backpressure trigger.
    let _body = response.into_body();
    let error = timeout(TEST_TIMEOUT, connection)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(error.reason(), Some(Reason::ENHANCE_YOUR_CALM));
    timeout(TEST_TIMEOUT, malicious_peer)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn too_many_empty_data_frames_sends_goaway() {
    assert_excess_frames_close_connection(vec![(0, vec![]); 101]).await;
}

#[tokio::test]
async fn too_many_padded_empty_data_frames_sends_goaway() {
    // Padding length = 1 followed by one padding byte: no decoded application data.
    assert_excess_frames_close_connection(vec![(8, vec![1, 0]); 101]).await;
}

#[tokio::test]
async fn too_many_small_data_frames_sends_goaway() {
    let mut frames = vec![(0, vec![b'a']); 50];
    frames.push((0, vec![0; 2048])); // replenish part of the framing budget
    frames.extend(vec![(0, vec![b'a']); 101]);
    assert_excess_frames_close_connection(frames).await;
}

#[tokio::test]
async fn recv_ignores_empty_data_without_end_stream() {
    let (io, mut peer) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        respond(&mut peer).await;
        for _ in 0..49 {
            write_frame(&mut peer, 0, 0, 1, &[]).await;
        }
        for _ in 0..50 {
            write_frame(&mut peer, 0, 8, 1, &[1, 0]).await;
        }
        write_frame(&mut peer, 0, 1, 1, b"hello").await;
    });
    let (mut client, connection) = client::handshake(io).await.unwrap();
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    let response = client.send_request(request, true).unwrap().0.await.unwrap();
    let mut body = response.into_body();
    assert_eq!(
        body.data().await.unwrap().unwrap(),
        Bytes::from_static(b"hello")
    );
    assert!(body.data().await.is_none());
    timeout(TEST_TIMEOUT, peer).await.unwrap().unwrap();
    connection.abort();
}

#[tokio::test]
async fn empty_end_stream_still_completes_body() {
    let (io, mut peer) = tokio::io::duplex(64 * 1024);
    let peer = tokio::spawn(async move {
        respond(&mut peer).await;
        write_frame(&mut peer, 0, 1, 1, &[]).await;
    });
    let (mut client, connection) = client::handshake(io).await.unwrap();
    let connection = tokio::spawn(connection);
    let request = Request::builder()
        .uri("https://example.com/")
        .body(())
        .unwrap();
    let response = client.send_request(request, true).unwrap().0.await.unwrap();
    let mut body = response.into_body();
    assert!(body.data().await.unwrap().unwrap().is_empty());
    assert!(body.data().await.is_none());
    timeout(TEST_TIMEOUT, peer).await.unwrap().unwrap();
    connection.abort();
}
