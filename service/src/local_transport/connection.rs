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

/// Why no request line was read.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ReadError {
    /// No newline within [`MAX_REQUEST_BYTES`], bytes after the newline, or
    /// the end of the stream before the newline: answered `invalid_request`.
    Malformed,
    /// No byte within the idle timeout: closed without a response.
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

/// Reads one request line of at most `limit` bytes, its newline included,
/// and returns it without the newline. Never holds more than `limit` bytes:
/// each read asks for no more than the room left. Each read must return
/// within `idle`.
pub(super) async fn read_line(
    stream: &UnixStream,
    limit: usize,
    idle: Duration,
) -> Result<Vec<u8>, ReadError> {
    let mut line = Vec::new();
    let mut chunk = vec![0; limit.min(8 * 1024)];
    loop {
        let room = limit - line.len();
        if room == 0 {
            return Err(ReadError::Malformed);
        }
        let want = room.min(chunk.len());
        let read = timeout(idle, read_some(stream, &mut chunk[..want]))
            .await
            .map_err(|_| ReadError::Idle)?
            .map_err(|_| ReadError::Io)?;
        if read == 0 {
            return Err(ReadError::Malformed);
        }
        let received = &chunk[..read];
        if let Some(at) = received.iter().position(|byte| *byte == b'\n') {
            if at + 1 != read {
                return Err(ReadError::Malformed);
            }
            line.extend_from_slice(&received[..at]);
            return Ok(line);
        }
        line.extend_from_slice(received);
    }
}

/// Serves one connection within the transport's per-connection deadline;
/// past it the connection is dropped (see the module docs, "Time limits").
pub(super) async fn serve(stream: UnixStream, shared: &Shared) {
    let deadline = Instant::now() + shared.settings.deadline;
    let _ = timeout_at(deadline, exchange(&stream, shared)).await;
}

/// The peer check, the request and the response line.
async fn exchange(stream: &UnixStream, shared: &Shared) {
    let reply = match answer(stream, shared).await {
        Some(reply) => reply,
        None => return,
    };
    let _ = write_all(stream, &reply.line()).await;
}

/// The reply to the connection's request, or `None` to close it without
/// one.
async fn answer(stream: &UnixStream, shared: &Shared) -> Option<Reply> {
    let peer_uid = stream.peer_cred().ok().map(|credentials| credentials.uid());
    if !peer_allowed(peer_uid, shared.service_uid) {
        return Some(refusal(ErrorCode::Forbidden));
    }
    let line = match read_line(stream, MAX_REQUEST_BYTES, shared.settings.idle_timeout).await {
        Ok(line) => line,
        Err(ReadError::Malformed) => return Some(refusal(ErrorCode::InvalidRequest)),
        Err(ReadError::Idle | ReadError::Io) => return None,
    };
    let Ok(request) = serde_json::from_slice::<Request>(&line) else {
        return Some(refusal(ErrorCode::InvalidRequest));
    };
    // One request at a time per transport (see the module docs,
    // "Serialization").
    let _serial = shared.serial.lock().await;
    Some(ops::execute(shared, request).await)
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

    /// Writes `bytes` from the client end in one go and closes it unless
    /// `keep_open`, then reads a line with `limit`.
    async fn line_of(bytes: &[u8], limit: usize, keep_open: bool) -> Result<Vec<u8>, ReadError> {
        let (server, client) = UnixStream::pair().unwrap();
        let bytes = bytes.to_vec();
        let writer = tokio::spawn(async move {
            let _ = write_all(&client, &bytes).await;
            if keep_open {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            drop(client);
        });
        let line = read_line(&server, limit, IDLE).await;
        writer.abort();
        line
    }

    #[tokio::test]
    async fn a_line_is_read_up_to_its_newline() {
        assert_eq!(line_of(b"{}\n", 64, true).await, Ok(b"{}".to_vec()));
        assert_eq!(line_of(b"\n", 64, true).await, Ok(Vec::new()));
        // Exactly the limit, newline included.
        let full = [b"x".repeat(63), b"\n".to_vec()].concat();
        assert_eq!(line_of(&full, 64, true).await, Ok(b"x".repeat(63)));
    }

    #[tokio::test]
    async fn a_line_over_the_limit_is_refused_without_reading_on() {
        let over = [b"x".repeat(64), b"\n".to_vec()].concat();
        assert_eq!(line_of(&over, 64, true).await, Err(ReadError::Malformed));
        let long = b"x".repeat(MAX_REQUEST_BYTES * 4);
        assert_eq!(
            line_of(&long, MAX_REQUEST_BYTES, true).await,
            Err(ReadError::Malformed)
        );
    }

    #[tokio::test]
    async fn trailing_bytes_and_a_missing_newline_are_refused() {
        assert_eq!(
            line_of(b"{}\n{}", 64, true).await,
            Err(ReadError::Malformed)
        );
        assert_eq!(
            line_of(b"{}\n\n", 64, true).await,
            Err(ReadError::Malformed)
        );
        assert_eq!(line_of(b"{}", 64, false).await, Err(ReadError::Malformed));
        assert_eq!(line_of(b"", 64, false).await, Err(ReadError::Malformed));
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (server, _client) = UnixStream::pair().unwrap();
        assert_eq!(
            read_line(&server, 64, Duration::from_millis(50)).await,
            Err(ReadError::Idle)
        );
    }

    #[test]
    fn a_refusal_is_its_code() {
        assert_eq!(
            refusal(ErrorCode::NotRestorable).line(),
            b"{\"error\":\"not_restorable\"}\n"
        );
    }
}
