//! One connection: the peer check, the bounded read of one request line,
//! the request in the transport's critical section, and the response line
//! (see the module docs of [`crate::local_transport`], "Protocol").

use std::{io, time::Duration};

use tokio::{
    net::UnixStream,
    time::{Instant, timeout, timeout_at},
};

use super::{
    Shared,
    error::ErrorCode,
    ops,
    wire::{Reply, Request},
};

/// The largest request line, its newline included: 64 KiB.
pub const MAX_REQUEST_BYTES: usize = 64 * 1024;

/// The UID that is always accepted besides the service UID.
const ROOT_UID: u32 = 0;

/// Whether a peer with the credentials' UID `peer_uid` may use the
/// transport: only the service UID and root. No credentials, no access.
pub(super) fn peer_allowed(peer_uid: Option<u32>, service_uid: u32) -> bool {
    peer_uid.is_some_and(|uid| uid == service_uid || uid == ROOT_UID)
}

/// Why no request was read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadError {
    /// No newline within [`MAX_REQUEST_BYTES`], a byte after the newline, or
    /// the end of the stream before the newline: answered `invalid_request`.
    Malformed,
    /// No byte and no end of stream within the idle timeout: closed without
    /// a response.
    Idle,
    /// A read failed: closed without a response.
    Io,
}

/// Reads at most `buf.len()` bytes into `buf`, waiting for readiness.
async fn read_some(stream: &UnixStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        stream.readable().await?;
        match stream.try_read(buf) {
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
    }
}

/// Writes all of `bytes`, waiting for readiness.
async fn write_all(stream: &UnixStream, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.writable().await?;
        match stream.try_write(bytes) {
            Ok(written) => bytes = &bytes[written..],
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

/// Reads one request: a line of at most `limit` bytes, its newline
/// included, and then the end of the stream (the client closes its write
/// half), and returns the line without its newline. However the bytes are
/// split across reads, the result is the same: a byte after the newline,
/// in the newline's read or a later one, is [`ReadError::Malformed`], and
/// the request is returned only once the end of the stream is read. Never
/// holds more than `limit` bytes: each read asks for no more than the room
/// left (one byte once the newline is in). Each read must return within
/// `idle`.
pub(super) async fn read_request(
    stream: &UnixStream,
    limit: usize,
    idle: Duration,
) -> Result<Vec<u8>, ReadError> {
    let mut line = Vec::new();
    let mut chunk = vec![0; limit.clamp(1, 8 * 1024)];
    let mut complete = false;
    loop {
        let want = if complete {
            1
        } else {
            let room = limit - line.len();
            if room == 0 {
                return Err(ReadError::Malformed);
            }
            room.min(chunk.len())
        };
        let read = timeout(idle, read_some(stream, &mut chunk[..want]))
            .await
            .map_err(|_| ReadError::Idle)?
            .map_err(|_| ReadError::Io)?;
        if read == 0 {
            return if complete {
                Ok(line)
            } else {
                Err(ReadError::Malformed)
            };
        }
        if complete {
            return Err(ReadError::Malformed);
        }
        let received = &chunk[..read];
        if let Some(at) = received.iter().position(|byte| *byte == b'\n') {
            if at + 1 != read {
                return Err(ReadError::Malformed);
            }
            line.extend_from_slice(&received[..at]);
            complete = true;
        } else {
            line.extend_from_slice(received);
        }
    }
}

/// Serves one connection (see the module docs, "Time limits"): the
/// connection's deadline bounds the read of the request, the wait for the
/// transport's mutex and the pool's acquire; once its transaction has
/// begun, the request runs to its end (bounded by the statement and lock
/// timeouts), and the response is written within the idle timeout.
pub(super) async fn serve(stream: UnixStream, shared: &Shared) {
    // `Settings` bound the deadline (`MAX_TIMEOUT`): it always fits.
    let Some(deadline) = Instant::now().checked_add(shared.settings.deadline) else {
        return;
    };
    let Some(reply) = answer(&stream, shared, deadline).await else {
        return;
    };
    let _ = timeout(
        shared.settings.idle_timeout,
        write_all(&stream, &reply.line()),
    )
    .await;
}

/// The reply to the connection's request, or `None` to close it without
/// one.
async fn answer(stream: &UnixStream, shared: &Shared, deadline: Instant) -> Option<Reply> {
    // Before any read: a refused peer is answered at once.
    let peer_uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
    if !peer_allowed(peer_uid, shared.service_uid) {
        return Some(refusal(ErrorCode::Forbidden));
    }
    let read = read_request(stream, MAX_REQUEST_BYTES, shared.settings.idle_timeout);
    let line = match timeout_at(deadline, read).await.ok()? {
        Ok(line) => line,
        Err(ReadError::Malformed) => return Some(refusal(ErrorCode::InvalidRequest)),
        Err(ReadError::Idle | ReadError::Io) => return None,
    };
    let Some(request) = Request::parse(&line) else {
        return Some(refusal(ErrorCode::InvalidRequest));
    };
    // One request at a time per transport (see the module docs,
    // "Serialization"), taken only once the request is read, and held until
    // its transaction has ended.
    let _serial = timeout_at(deadline, shared.serial.lock()).await.ok()?;
    ops::execute(shared, request, deadline).await
}

/// The refusal with `code`.
pub(super) const fn refusal(code: ErrorCode) -> Reply {
    Reply::Error {
        error: code.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IDLE: Duration = Duration::from_secs(5);

    #[test]
    fn only_the_service_uid_and_root_are_allowed() {
        assert!(peer_allowed(Some(1000), 1000));
        assert!(peer_allowed(Some(0), 1000));
        assert!(peer_allowed(Some(0), 0));
        assert!(!peer_allowed(Some(1001), 1000));
        assert!(!peer_allowed(Some(1), 0));
        assert!(!peer_allowed(Some(u32::MAX), 1000));
        assert!(!peer_allowed(None, 1000));
        assert!(!peer_allowed(None, 0));
    }

    /// Writes `bytes` from the client end, in `pieces` writes with a pause
    /// between them, then closes the write half unless `keep_open`, and
    /// reads a request with `limit` and `idle`.
    async fn request_of(
        pieces: &[&[u8]],
        limit: usize,
        idle: Duration,
        keep_open: bool,
    ) -> Result<Vec<u8>, ReadError> {
        let (server, client) = UnixStream::pair().unwrap();
        let pieces: Vec<Vec<u8>> = pieces.iter().map(|piece| piece.to_vec()).collect();
        let writer = tokio::spawn(async move {
            for piece in pieces {
                let _ = write_all(&client, &piece).await;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            let client = client.into_std().unwrap();
            if keep_open {
                tokio::time::sleep(Duration::from_secs(60)).await;
            } else {
                let _ = client.shutdown(std::net::Shutdown::Write);
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            drop(client);
        });
        let request = read_request(&server, limit, idle).await;
        writer.abort();
        request
    }

    async fn whole(bytes: &[u8], limit: usize) -> Result<Vec<u8>, ReadError> {
        request_of(&[bytes], limit, IDLE, false).await
    }

    #[tokio::test]
    async fn a_request_is_its_line_and_the_end_of_the_stream() {
        assert_eq!(whole(b"{}\n", 64).await, Ok(b"{}".to_vec()));
        assert_eq!(whole(b"\n", 64).await, Ok(Vec::new()));
        // Exactly the limit, newline included.
        let full = [b"x".repeat(63), b"\n".to_vec()].concat();
        assert_eq!(whole(&full, 64).await, Ok(b"x".repeat(63)));
        // A line read in many pieces, and its newline alone.
        assert_eq!(
            request_of(&[b"{", b"\"a\":", b"1}", b"\n"], 64, IDLE, false).await,
            Ok(b"{\"a\":1}".to_vec())
        );
    }

    #[tokio::test]
    async fn a_line_over_the_limit_is_refused_without_reading_on() {
        let over = [b"x".repeat(64), b"\n".to_vec()].concat();
        assert_eq!(whole(&over, 64).await, Err(ReadError::Malformed));
        let long = b"x".repeat(MAX_REQUEST_BYTES * 4);
        assert_eq!(
            request_of(&[&long], MAX_REQUEST_BYTES, IDLE, true).await,
            Err(ReadError::Malformed)
        );
    }

    #[tokio::test]
    async fn a_byte_after_the_newline_is_refused_however_it_arrives() {
        for pieces in [
            &[&b"{}\n{}"[..]][..],
            &[b"{}\n\n"],
            &[b"{}\n", b"{}"],
            &[b"{}\n", b"\n"],
            &[b"{}", b"\n", b" "],
            &[b"{}", b"\nx"],
        ] {
            assert_eq!(
                request_of(pieces, 64, IDLE, false).await,
                Err(ReadError::Malformed),
                "{pieces:?}"
            );
            // Not waiting for the end of the stream either.
            assert_eq!(
                request_of(pieces, 64, IDLE, true).await,
                Err(ReadError::Malformed),
                "{pieces:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_same_bytes_in_any_pieces_read_the_same() {
        let line: &[u8] = b"{\"op\":\"restore\"}\n";
        let expected = whole(line, 64).await;
        assert_eq!(expected, Ok(line[..line.len() - 1].to_vec()));
        for cut in 1..line.len() {
            let (head, tail) = line.split_at(cut);
            assert_eq!(request_of(&[head, tail], 64, IDLE, false).await, expected);
        }
    }

    #[tokio::test]
    async fn a_missing_newline_or_end_of_stream_is_not_a_request() {
        assert_eq!(whole(b"{}", 64).await, Err(ReadError::Malformed));
        assert_eq!(whole(b"", 64).await, Err(ReadError::Malformed));
        // A complete line without the end of the stream: no request.
        let idle = Duration::from_millis(100);
        assert_eq!(
            request_of(&[b"{}\n"], 64, idle, true).await,
            Err(ReadError::Idle)
        );
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (server, _client) = UnixStream::pair().unwrap();
        assert_eq!(
            read_request(&server, 64, Duration::from_millis(50)).await,
            Err(ReadError::Idle)
        );
    }

    /// An ID generator that is never reached.
    struct NoIds;

    impl crate::ids::IdGenerator for NoIds {
        fn new_id(&self, _kind: crate::ids::IdKind) -> Result<String, crate::ids::IdError> {
            Err(crate::ids::IdError::SourceFailed)
        }
    }

    /// The process's effective UID, as the peer check sees it.
    fn own_uid() -> u32 {
        let (one, _other) = UnixStream::pair().unwrap();
        one.peer_cred().unwrap().uid()
    }

    /// A refused peer is answered `forbidden` at once, before any read: a
    /// peer that sends nothing is not left waiting for the idle timeout. A
    /// refused peer needs a UID that is neither the service UID nor root, so
    /// this runs only when the tests do not run as root (as in CI); as root,
    /// `tests/local_transport.rs`'s `a_peer_of_another_uid_is_refused`
    /// covers it with a second user.
    #[tokio::test]
    async fn a_refused_peer_is_answered_before_any_read() {
        let uid = own_uid();
        if uid == ROOT_UID {
            eprintln!("NOTICE: running as root: the in-process refused-peer check was NOT run");
            return;
        }
        let options = sqlx::postgres::PgConnectOptions::new()
            .host("127.0.0.1")
            .port(1);
        let shared = std::sync::Arc::new(Shared {
            pool: sqlx::postgres::PgPoolOptions::new().connect_lazy_with(options),
            clock: std::sync::Arc::new(crate::operation::SystemClock),
            ids: std::sync::Arc::new(NoIds),
            settings: super::super::Settings {
                idle_timeout: Duration::from_secs(30),
                ..super::super::Settings::default()
            },
            service_uid: uid.wrapping_add(1),
            serial: tokio::sync::Mutex::new(()),
        });
        let (server, client) = UnixStream::pair().unwrap();
        let task = tokio::spawn({
            let shared = std::sync::Arc::clone(&shared);
            async move { serve(server, &shared).await }
        });
        let mut reply = vec![0; 64];
        let read = timeout(Duration::from_secs(5), read_some(&client, &mut reply))
            .await
            .expect("answered before the idle timeout")
            .unwrap();
        assert_eq!(&reply[..read], b"{\"error\":\"forbidden\"}\n");
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[test]
    fn a_refusal_is_its_code() {
        assert_eq!(
            refusal(ErrorCode::NotRestorable).line(),
            b"{\"error\":\"not_restorable\"}\n"
        );
    }
}
