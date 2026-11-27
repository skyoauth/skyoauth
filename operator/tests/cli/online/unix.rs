//! The online commands against a fake service on a Unix socket (see
//! [`super`]).

use std::{
    ffi::OsString,
    fs,
    io::{self, Read as _, Write as _},
    os::unix::{
        fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
        net::UnixListener,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use serde_json::Value;
use skyoauth_operator::local::{
    AncestorTrust, CallError, DEFAULT_IDLE_WAIT, DEFAULT_TOTAL_WAIT, ErrorCode, Op,
    SocketExpectations, UnknownOutcome, check_socket, parse_reply,
};

use super::{Run, SIGNATURE, SPKI_HEX, UNCHANGED_NEXT, online};
use crate::{
    local_wire::wire_fixture,
    support::{list, text, unhex},
};

/// The longest a fake service waits for a connection or a peer.
const TEST_WAIT: Duration = Duration::from_secs(10);

/// The operation of the fixture's golden requests.
const OPERATION: &str = "oper_0000000000000g000000000001";

/// The values of the fixture's golden `bootstrap`, which its
/// `status_bootstrapped` reports.
const INSTANCE: &str = "019a9f3c-5b2e-7c41-9d8e-0000000c1001";
const ANCHOR: &str = "deployment/operator-ca";
const RECOVERY_KEY: &str = "c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a";

/// The end of a successful `status` and `preview`.
const STATUS_OK: &str = "result: ok; the service answered; status changes nothing\n";
const PREVIEW_OK: &str =
    "result: ok; the service previewed the restore of this response; nothing was written\n";

/// A fresh directory of mode 0700 under the system's temporary directory,
/// removed when dropped: the socket's private directory, which the test's
/// own user owns (root included).
struct Private(PathBuf);

impl Private {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "sko-online-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    /// Writes `bytes` to the file `name` in the directory, and returns its
    /// path.
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// The directory's owner: the `--service-uid` a socket in it passes
    /// with.
    fn owner(&self) -> u32 {
        fs::metadata(&self.0).unwrap().uid()
    }
}

impl Drop for Private {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// What the fake service does with a connection, once it has read the
/// request to its end.
enum Answer {
    /// Writes these bytes and closes.
    Line(Vec<u8>),
    /// Writes these bytes, then waits until the run is over.
    Stall(Vec<u8>),
}

/// A fake service: a listener at `s`, mode 0600, in a [`Private`]
/// directory, that answers its connections in order with its answers and
/// keeps every request it read. A connection after the last answer is
/// read and closed unanswered.
struct Fake {
    dir: Private,
    socket: PathBuf,
    done: Arc<AtomicBool>,
    server: Option<thread::JoinHandle<Vec<Vec<u8>>>>,
}

impl Fake {
    fn new(answers: Vec<Answer>) -> Self {
        let dir = Private::new();
        let socket = dir.0.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let done = Arc::new(AtomicBool::new(false));
        let server_done = Arc::clone(&done);
        let server = thread::spawn(move || serve(&listener, answers, &server_done));
        Self {
            dir,
            socket,
            done,
            server: Some(server),
        }
    }

    /// A fake service that answers each of `lines` in order.
    fn lines(lines: &[Vec<u8>]) -> Self {
        Self::new(lines.iter().cloned().map(Answer::Line).collect())
    }

    /// The socket flags of this service.
    fn flags(&self) -> Vec<OsString> {
        vec![
            "--socket".into(),
            self.socket.clone().into(),
            "--service-uid".into(),
            self.dir.owner().to_string().into(),
        ]
    }

    /// The paths no output may name.
    fn hidden(&self) -> Vec<String> {
        vec![
            self.socket.display().to_string(),
            self.dir.0.display().to_string(),
        ]
    }

    /// Runs `command` with this service's socket flags and `rest`.
    fn run(&self, command: &str, rest: &[OsString]) -> Run {
        let mut arguments: Vec<OsString> = vec![command.into()];
        arguments.extend(self.flags());
        arguments.extend(rest.iter().cloned());
        online(&arguments, &self.hidden())
    }

    /// Ends the service once the run is over: the request of every
    /// connection it accepted, in order.
    fn finish(mut self) -> Vec<Vec<u8>> {
        self.done.store(true, Ordering::SeqCst);
        self.server
            .take()
            .unwrap()
            .join()
            .expect("the fake service's checks")
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.done.store(true, Ordering::SeqCst);
    }
}

/// The fake service's thread: accepts until the run is over (bounded),
/// reads each request to the end of its stream (the client closes its
/// write half) and answers it.
fn serve(listener: &UnixListener, answers: Vec<Answer>, done: &AtomicBool) -> Vec<Vec<u8>> {
    listener.set_nonblocking(true).unwrap();
    let mut answers = answers.into_iter();
    let mut received = Vec::new();
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(TEST_WAIT)).unwrap();
                stream.set_write_timeout(Some(TEST_WAIT)).unwrap();
                let mut request = Vec::new();
                let _ = stream.read_to_end(&mut request);
                received.push(request);
                match answers.next() {
                    Some(Answer::Line(line)) => {
                        let _ = stream.write_all(&line);
                    }
                    Some(Answer::Stall(start_of_line)) => {
                        let _ = stream.write_all(&start_of_line);
                        wait_until(done);
                    }
                    None => {}
                }
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                // Bounded, so a test that fails before `finish` ends too.
                if done.load(Ordering::SeqCst) || start.elapsed() > 6 * TEST_WAIT {
                    return received;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(err) => panic!("accept: {err}"),
        }
    }
}

/// Blocks until `done` (bounded by [`TEST_WAIT`] several times over).
fn wait_until(done: &AtomicBool) {
    let start = Instant::now();
    while !done.load(Ordering::SeqCst) && start.elapsed() < 6 * TEST_WAIT {
        thread::sleep(Duration::from_millis(5));
    }
}

/// The golden request line of the fixture's case `name`.
fn golden_request(name: &str) -> Vec<u8> {
    golden("golden_requests", name)
}

/// The golden reply line of the fixture's case `name`.
fn golden_reply(name: &str) -> Vec<u8> {
    golden("golden_replies", name)
}

fn golden(list_name: &str, name: &str) -> Vec<u8> {
    text(golden_case(list_name, name), "line")
        .as_bytes()
        .to_vec()
}

fn golden_case(list_name: &str, name: &str) -> &'static Value {
    static FIXTURE: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    list(FIXTURE.get_or_init(wire_fixture), list_name)
        .iter()
        .find(|case| text(case, "case") == name)
        .unwrap_or_else(|| panic!("no {list_name} case {name}"))
}

/// The values of the golden reply `name`.
fn golden_values(name: &str) -> Value {
    golden_case("golden_replies", name)["values"].clone()
}

/// The members of a `status` reply, in the service's order, and their
/// types (the fixture's `replies`).
fn status_members() -> Vec<(String, String)> {
    list(&wire_fixture()["replies"]["status"], "members")
        .iter()
        .map(|member| {
            (
                member[0].as_str().unwrap().to_owned(),
                member[1].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

/// The `status` reply line of `values`, its members in the service's
/// order and each value as `serde_json` writes it (as the service does).
fn status_line(values: &Value) -> Vec<u8> {
    let members: Vec<String> = status_members()
        .iter()
        .map(|(name, _)| {
            format!(
                "\"{name}\":{}",
                serde_json::to_string(&values[name.as_str()]).unwrap()
            )
        })
        .collect();
    format!("{{{}}}\n", members.join(",")).into_bytes()
}

/// `text` as the binary must print a string: quoted, printable ASCII but
/// `"` and `\` as is, those after a backslash, every other character as
/// `\u{X}` (written here independently of the binary).
fn shown(text: &str) -> String {
    let mut out = String::from("\"");
    for character in text.chars() {
        match character {
            '"' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            ' '..='~' => out.push(character),
            other => out.push_str(&format!("\\u{{{:x}}}", u32::from(other))),
        }
    }
    out.push('"');
    out
}

/// The output the binary must print for the `status` reply `values`: one
/// line per member in the service's order, `null` as `null`, strings
/// quoted, states as they are, integers in decimal, byte values in
/// hexadecimal; the revoked IDs (`walked`, else the reply's) as their
/// number and one line each.
fn status_output(values: &Value, walked: Option<&[String]>) -> String {
    let mut out = String::new();
    for (name, kind) in status_members() {
        let value = &values[name.as_str()];
        if name == "revoked_credential_ids" {
            let ids: Option<Vec<String>> = walked.map(<[String]>::to_vec).or_else(|| {
                value.as_array().map(|ids| {
                    ids.iter()
                        .map(|id| id.as_str().unwrap().to_owned())
                        .collect()
                })
            });
            match ids {
                None => out.push_str("revoked_credential_ids: null\n"),
                Some(ids) => {
                    out.push_str(&format!("revoked_credential_ids: {}\n", ids.len()));
                    for id in ids {
                        out.push_str(&format!("revoked_credential_id: {}\n", shown(&id)));
                    }
                }
            }
            continue;
        }
        let shown_value = match value {
            Value::Null => "null".to_owned(),
            Value::Number(number) => number.to_string(),
            Value::String(string) if name.ends_with("_state") || kind.starts_with("hex") => {
                string.clone()
            }
            Value::String(string) => shown(string),
            other => panic!("{name}: {other}"),
        };
        out.push_str(&format!("{name}: {shown_value}\n"));
    }
    out
}

/// The response artifact of the fixture's golden `preview` request: its
/// line without the `op` member.
fn golden_response() -> Vec<u8> {
    let line = String::from_utf8(golden_request("preview")).unwrap();
    line.replacen("\"op\":\"preview\",", "", 1).into_bytes()
}

/// A response artifact of `operation_id` and `signature` (hexadecimal).
fn response_artifact(operation_id: &str, signature: &str) -> Vec<u8> {
    format!(
        "{{\"operation_id\":{},\"signature\":\"{signature}\"}}\n",
        serde_json::to_string(operation_id).unwrap()
    )
    .into_bytes()
}

/// The `status` request of the golden operation after `after`, written as
/// the fixture's `status_revoked_after` line with its ID replaced.
fn status_after(after: &str) -> Vec<u8> {
    let line = String::from_utf8(golden_request("status_revoked_after")).unwrap();
    let golden_after = text(
        &golden_case("golden_requests", "status_revoked_after")["values"],
        "revoked_after",
    );
    line.replacen(
        &format!("\"revoked_after\":\"{golden_after}\""),
        &format!("\"revoked_after\":\"{after}\""),
        1,
    )
    .into_bytes()
}

fn path_flag(flag: &str, path: &Path) -> Vec<OsString> {
    vec![flag.into(), path.into()]
}

/// `preview` of the golden response: the request received is the golden
/// `preview` line byte for byte, over one connection; the reply's members
/// are printed in order, the signature never.
#[test]
fn preview_sends_the_golden_request_and_prints_the_reply() {
    let fake = Fake::lines(&[golden_reply("previewed")]);
    let response = fake.dir.file("response", &golden_response());
    let run = fake.run("preview", &path_flag("--response", &response));
    assert_eq!(fake.finish(), [golden_request("preview")]);
    assert_eq!(
        run,
        Run {
            code: 0,
            stdout: format!(
                "admin_id: \"adm_0000000000000g000000000002\"\n\
                 credential_id: \"cred_0000000000000g000000000002\"\n\
                 binding_id: \"role_0000000000000g000000000002\"\n\
                 new_recovery_key_epoch: 2\n\
                 expires_at: 1790000300000000\n{PREVIEW_OK}"
            ),
            stderr: String::new(),
        }
    );
}

/// Each form of `status` sends the fixture's golden request and prints
/// every member of the golden reply: no selector; `--credential-spki` (the
/// DER file); `--response` and `--challenge` (the golden issued reply as
/// the challenge artifact), whose restored operation is followed by the
/// walk of its revoked IDs from `status` alone (one more golden
/// `status_operation` request).
#[test]
fn each_status_form_sends_its_golden_request() {
    let fake = Fake::lines(&[golden_reply("status_nothing")]);
    let run = fake.run("status", &[]);
    assert_eq!(fake.finish(), [golden_request("status_empty")]);
    assert_eq!(
        run.stdout,
        format!(
            "{}{STATUS_OK}",
            status_output(&golden_values("status_nothing"), None)
        )
    );
    assert_eq!(run.code, 0, "{run:?}");

    let fake = Fake::lines(&[golden_reply("status_bootstrapped")]);
    let spki = fake.dir.file("spki", &unhex(SPKI_HEX));
    let run = fake.run("status", &path_flag("--credential-spki", &spki));
    assert_eq!(fake.finish(), [golden_request("status_credential")]);
    assert_eq!(
        run.stdout,
        format!(
            "{}{STATUS_OK}",
            status_output(&golden_values("status_bootstrapped"), None)
        )
    );
    assert!(
        run.stdout.contains("\nenrolled_state: enabled\n"),
        "{run:?}"
    );

    for (flag, artifact) in [
        ("--response", golden_response()),
        ("--challenge", golden_reply("issued")),
    ] {
        let fake = Fake::lines(&[
            golden_reply("status_restored"),
            golden_reply("status_restored"),
        ]);
        let path = fake.dir.file("artifact", &artifact);
        let run = fake.run("status", &path_flag(flag, &path));
        assert_eq!(
            fake.finish(),
            [
                golden_request("status_operation"),
                golden_request("status_operation")
            ],
            "{flag}"
        );
        let expected = status_output(&golden_values("status_restored"), None);
        assert_eq!(run.stdout, format!("{expected}{STATUS_OK}"), "{flag}");
        assert!(
            expected.contains(
                "revoked_credential_count: 1\nrevoked_credential_ids: 1\n\
                 revoked_credential_id: \"cred_0000000000000g000000000001\"\n"
            ),
            "{expected}"
        );
        assert!(!run.stdout.contains("verdict:"), "{run:?}");
    }
}

/// The builder of `status` replies writes the golden lines.
#[test]
fn the_status_lines_built_here_are_the_golden_ones() {
    for name in [
        "status_nothing",
        "status_bootstrapped",
        "status_restored",
        "status_restored_after",
    ] {
        assert_eq!(
            status_line(&golden_values(name)),
            golden_reply(name),
            "{name}"
        );
    }
    assert_eq!(status_after(OPERATION), {
        let line = String::from_utf8(golden_request("status_revoked_after")).unwrap();
        line.replace("cred_0000000000000g000000000001", OPERATION)
            .into_bytes()
    });
}

/// The IDs `cred_000000` to the one before `count`, in byte order.
fn ids(count: usize) -> Vec<String> {
    (0..count).map(|at| format!("cred_{at:06}")).collect()
}

/// The golden restored `status` with `count` revoked and `page` listed.
fn restored(count: usize, page: &[String]) -> Vec<u8> {
    let mut values = golden_values("status_restored");
    values["revoked_credential_count"] = Value::from(count);
    values["revoked_credential_ids"] = Value::from(page.to_vec());
    status_line(&values)
}

/// The walk over several pages: 2500 revoked IDs read as the reply's page
/// and then two pages after the last ID held, each request the golden one
/// (`revoked_after` the last ID held); every ID printed once, in order.
#[test]
fn status_walks_every_revoked_id_over_pages() {
    let all = ids(2500);
    let fake = Fake::lines(&[
        restored(2500, &all[..1000]),
        restored(2500, &all[..1000]),
        restored(2500, &all[1000..2000]),
        restored(2500, &all[2000..]),
    ]);
    let response = fake.dir.file("response", &golden_response());
    let run = fake.run("status", &path_flag("--response", &response));
    assert_eq!(
        fake.finish(),
        [
            golden_request("status_operation"),
            golden_request("status_operation"),
            status_after(&all[999]),
            status_after(&all[1999]),
        ]
    );
    let mut values = golden_values("status_restored");
    values["revoked_credential_count"] = Value::from(2500);
    assert_eq!(
        run.stdout,
        format!("{}{STATUS_OK}", status_output(&values, Some(&all)))
    );
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout.matches("revoked_credential_id: ").count(), 2500);
}

/// The documented tie: a count that changes between `status` pages
/// restarts the walk once, from `status` alone, and the list printed is
/// the restarted walk's (the reply's own count printed as it came).
#[test]
fn a_tie_restarts_the_walk_once() {
    let all = ids(1002);
    let fake = Fake::lines(&[
        restored(1001, &all[..1000]),
        restored(1001, &all[..1000]),
        restored(1002, &all[1000..1002]),
        restored(1002, &all[..1000]),
        restored(1002, &all[1000..1002]),
    ]);
    let response = fake.dir.file("response", &golden_response());
    let run = fake.run("status", &path_flag("--response", &response));
    assert_eq!(
        fake.finish(),
        [
            golden_request("status_operation"),
            golden_request("status_operation"),
            status_after(&all[999]),
            golden_request("status_operation"),
            status_after(&all[999]),
        ]
    );
    let mut values = golden_values("status_restored");
    values["revoked_credential_count"] = Value::from(1001);
    assert_eq!(
        run.stdout,
        format!("{}{STATUS_OK}", status_output(&values, Some(&all)))
    );
}

/// Pages that do not hold together are an unknown outcome of a read:
/// exit 6, nothing on standard output, never 5. A first page shorter than
/// its count allows; a second tie after the restart. A walk's page refused
/// by the service is exit 1.
#[test]
fn pages_that_do_not_hold_together_are_exit_6() {
    let all = ids(1003);
    let mismatch = format!(
        "skyoauth-operator: the reply cannot be believed ({}); status changes nothing\n\
         {UNCHANGED_NEXT}",
        UnknownOutcome::PageMismatch
    );
    for (answers, requests) in [
        (
            vec![restored(2, &all[..1]), restored(2, &all[..1])],
            vec![golden_request("status_operation"); 2],
        ),
        (
            vec![
                restored(1001, &all[..1000]),
                restored(1001, &all[..1000]),
                restored(1002, &all[1000..1002]),
                restored(1002, &all[..1000]),
                restored(1003, &all[1000..1003]),
            ],
            vec![
                golden_request("status_operation"),
                golden_request("status_operation"),
                status_after(&all[999]),
                golden_request("status_operation"),
                status_after(&all[999]),
            ],
        ),
    ] {
        let fake = Fake::lines(&answers);
        let response = fake.dir.file("response", &golden_response());
        let run = fake.run("status", &path_flag("--response", &response));
        assert_eq!(fake.finish(), requests);
        assert_eq!(
            run,
            Run {
                code: 6,
                stdout: String::new(),
                stderr: mismatch.clone(),
            }
        );
    }
    let fake = Fake::lines(&[
        restored(1001, &all[..1000]),
        restored(1001, &all[..1000]),
        golden_reply("error_forbidden"),
    ]);
    let response = fake.dir.file("response", &golden_response());
    let run = fake.run("status", &path_flag("--response", &response));
    assert_eq!(fake.finish().len(), 3);
    assert_eq!(
        (run.code, run.stdout.as_str(), run.stderr),
        (
            1,
            "",
            format!(
                "skyoauth-operator: refused (forbidden): {}\n",
                CallError::Refused(ErrorCode::Forbidden)
            )
        )
    );
}

/// The golden `status_restored` reply with its operation in `state`: the
/// replacement and the revoked IDs only when restored, `settles_at` only
/// when expiring (when `settles` says so).
fn in_state(state: Option<&str>, settles: bool) -> Value {
    let mut values = golden_values("status_restored");
    if state != Some("restored") {
        for name in [
            "restored_at",
            "admin_id",
            "credential_id",
            "binding_id",
            "revoked_credential_count",
            "revoked_credential_ids",
        ] {
            values[name] = Value::Null;
        }
    }
    if state.is_none() || state == Some("not_found") {
        values["expires_at"] = Value::Null;
    }
    values["operation_state"] = state.map_or(Value::Null, Value::from);
    if settles {
        values["settles_at"] = Value::from(1_790_000_360_000_000_i64);
    }
    values
}

/// Every verdict of `status --reconcile restore`, with its `next:` line,
/// by the state of the operation; exit 0 whatever the verdict. The request
/// is the golden `status_operation`, read from `--response` or
/// `--challenge`; a restored operation's revoked IDs are walked as for a
/// plain `status`.
#[test]
fn every_restore_verdict_and_its_next_step() {
    let cases: [(Option<&str>, bool, &str, &str); 9] = [
        (
            Some("restored"),
            false,
            "committed",
            "the replacement's IDs and every revoked ID are listed; do not repeat",
        ),
        (
            Some("retired"),
            false,
            "never_commits",
            "issue a new challenge",
        ),
        (
            Some("revoked"),
            false,
            "never_commits",
            "issue a new challenge",
        ),
        (
            Some("issued"),
            false,
            "repeat_restore",
            "run the same restore; it restores or is not_restorable; then reconcile again",
        ),
        (
            Some("expiring"),
            true,
            "ask_again_after",
            "run status again after settles_at (printed with server_time); the CLI does not wait",
        ),
        (
            Some("expired"),
            false,
            "expired",
            "issue a new challenge; not final",
        ),
        (Some("not_found"), false, "unknown", "do not proceed"),
        (None, false, "unknown", "do not proceed"),
        // Expiring without its settles_at: not decided.
        (Some("expiring"), false, "unknown", "do not proceed"),
    ];
    for (state, settles, verdict, next) in cases {
        for flag in ["--response", "--challenge"] {
            let values = in_state(state, settles);
            let mut answers = vec![status_line(&values)];
            let mut requests = vec![golden_request("status_operation")];
            if state == Some("restored") {
                answers.push(status_line(&values));
                requests.push(golden_request("status_operation"));
            }
            let fake = Fake::lines(&answers);
            let artifact = if flag == "--response" {
                golden_response()
            } else {
                golden_reply("issued")
            };
            let path = fake.dir.file("artifact", &artifact);
            let mut rest = vec!["--reconcile".into(), "restore".into()];
            rest.extend(path_flag(flag, &path));
            let run = fake.run("status", &rest);
            assert_eq!(fake.finish(), requests, "{state:?} {flag}");
            assert_eq!(
                run,
                Run {
                    code: 0,
                    stdout: format!(
                        "{}verdict: {verdict}\nnext: {next}\n{STATUS_OK}",
                        status_output(&values, None)
                    ),
                    stderr: String::new(),
                },
                "{state:?} {flag}"
            );
        }
    }
}

/// Every verdict of `status --reconcile bootstrap`, with its `next:` line;
/// exit 0 whatever the verdict. The request is the golden
/// `status_credential` (the key alone), from the four flags of the golden
/// `bootstrap`.
#[test]
fn every_bootstrap_verdict_and_its_next_step() {
    let usable = "do not repeat; the credential is usable only when enabled";
    let mut disabled = golden_values("status_bootstrapped");
    disabled["enrolled_state"] = Value::from("disabled");
    let mut other_key = golden_values("status_bootstrapped");
    other_key["recovery_public_key"] =
        Value::from("2012cb90ca60e8e5d8daf66e2272d2233e0486d557e8c66141ed8920177d7eb7");
    let cases = [
        (
            golden_values("status_bootstrapped"),
            ANCHOR,
            "matches (enabled: yes)",
            usable,
        ),
        (disabled, ANCHOR, "matches (enabled: no)", usable),
        (
            golden_values("status_nothing"),
            ANCHOR,
            "repeat_bootstrap",
            "run the same bootstrap",
        ),
        (
            golden_values("status_bootstrapped"),
            "deployment/other-ca",
            "does_not_match",
            "do not claim the bootstrap committed; stop",
        ),
        (
            other_key,
            ANCHOR,
            "does_not_match",
            "do not claim the bootstrap committed; stop",
        ),
    ];
    for (values, anchor, verdict, next) in cases {
        let fake = Fake::lines(&[status_line(&values)]);
        let spki = fake.dir.file("spki", &unhex(SPKI_HEX));
        let mut rest: Vec<OsString> = ["--reconcile", "bootstrap", "--instance-id", INSTANCE]
            .map(OsString::from)
            .to_vec();
        rest.extend(path_flag("--credential-spki", &spki));
        rest.extend(["--trust-anchor", anchor, "--recovery-key", RECOVERY_KEY].map(OsString::from));
        let run = fake.run("status", &rest);
        assert_eq!(
            fake.finish(),
            [golden_request("status_credential")],
            "{verdict}"
        );
        assert_eq!(
            run,
            Run {
                code: 0,
                stdout: format!(
                    "{}verdict: {verdict}\nnext: {next}\n{STATUS_OK}",
                    status_output(&values, None)
                ),
                stderr: String::new(),
            },
            "{verdict}"
        );
    }
}

/// Each refusal code of the fixture, after `preview` and after `status`:
/// exit 1 with the code and the library's fixed text, nothing on standard
/// output; `auth_unavailable` and `server_error` too, which change nothing
/// after a read.
#[test]
fn each_refusal_is_exit_1() {
    for code in ErrorCode::ALL {
        for command in ["preview", "status"] {
            let fake = Fake::lines(&[golden_reply(&format!("error_{}", code.as_str()))]);
            let response = fake.dir.file("response", &golden_response());
            let run = fake.run(command, &path_flag("--response", &response));
            assert_eq!(fake.finish().len(), 1, "{code:?} {command}");
            assert_eq!(
                run,
                Run {
                    code: 1,
                    stdout: String::new(),
                    stderr: format!(
                        "skyoauth-operator: refused ({}): {}\n",
                        code.as_str(),
                        CallError::Refused(code)
                    ),
                },
                "{code:?} {command}"
            );
        }
    }
}

/// The bytes of a fixture case's `parts`.
fn parts(case: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in list(case, "parts") {
        match (part.get("text"), part.get("hex")) {
            (Some(text), None) => bytes.extend_from_slice(text.as_str().unwrap().as_bytes()),
            (None, Some(hex)) => bytes.extend(unhex(hex.as_str().unwrap())),
            _ => panic!("a part is text or hex: {part}"),
        }
    }
    bytes
}

/// Every unknown reply of the fixture for `preview` and `status`, the real
/// service's bytes changed as the fixture says: exit 6 (a read changes
/// nothing: never 5), the library's reason, nothing on standard output,
/// one connection.
#[test]
fn every_unknown_reply_of_a_read_is_exit_6() {
    let mut tried = 0;
    for case in list(&wire_fixture(), "unknown_replies") {
        let (op, command) = match text(case, "op") {
            "preview" => (Op::Preview, "preview"),
            "status" => (Op::Status, "status"),
            _ => continue,
        };
        let reply = parts(case);
        let Err(CallError::Unknown(why)) = parse_reply(op, &reply) else {
            panic!("{}: not unknown", text(case, "case"));
        };
        let fake = Fake::lines(&[reply]);
        let response = fake.dir.file("response", &golden_response());
        let run = fake.run(command, &path_flag("--response", &response));
        assert_eq!(fake.finish().len(), 1, "{}", text(case, "case"));
        assert_eq!(
            run,
            Run {
                code: 6,
                stdout: String::new(),
                stderr: format!(
                    "skyoauth-operator: the reply cannot be believed ({why}); {command} changes \
                     nothing\n{UNCHANGED_NEXT}"
                ),
            },
            "{}",
            text(case, "case")
        );
        tried += 1;
    }
    assert!(tried >= 20, "{tried}");
}

/// The waits: a service that reads the request and never answers is
/// unknown at `--total-wait`; one whose reply stops after its first bytes
/// at `--idle-wait`, long before the total. Both exit 6, after one
/// connection, within the test's bound.
#[test]
fn each_wait_ends_a_read_as_exit_6() {
    let timed_out = format!(
        "skyoauth-operator: the reply cannot be believed ({}); preview changes nothing\n\
         {UNCHANGED_NEXT}",
        UnknownOutcome::TimedOut
    );
    let previewed = golden_reply("previewed");
    for (answer, waits) in [
        (
            Answer::Stall(Vec::new()),
            ["--total-wait", "1", "--idle-wait", "30"],
        ),
        (
            Answer::Stall(previewed[..5].to_vec()),
            ["--total-wait", "30", "--idle-wait", "1"],
        ),
    ] {
        let fake = Fake::new(vec![answer]);
        let response = fake.dir.file("response", &golden_response());
        let mut rest = path_flag("--response", &response);
        rest.extend(waits.map(OsString::from));
        let start = Instant::now();
        let run = fake.run("preview", &rest);
        let took = start.elapsed();
        assert_eq!(fake.finish(), [golden_request("preview")], "{waits:?}");
        assert_eq!(
            run,
            Run {
                code: 6,
                stdout: String::new(),
                stderr: timed_out.clone(),
            },
            "{waits:?}"
        );
        assert!(
            took >= Duration::from_millis(900) && took < TEST_WAIT,
            "{waits:?}: {took:?}"
        );
    }
}

/// The message of a socket path the client refuses, as the binary words
/// it: the flag and the library's fixed text of the problem.
fn refused_path(problem: impl std::fmt::Display) -> String {
    format!("skyoauth-operator: the request was not sent: --socket: {problem}\n{UNCHANGED_NEXT}")
}

/// The socket paths the client refuses before it connects: exit 6, the
/// problem named, no path printed, and nothing received by the service
/// (no connection at all). A socket of mode 0666; a shared (sticky)
/// directory; a directory others may write; nothing at the path; a
/// regular file there; another expected owner and `root-only`, whose
/// outcome for the test's user is the library's `check_socket`'s.
#[test]
fn each_refused_socket_path_is_exit_6_with_nothing_sent() {
    let response = golden_response();
    let preview = |fake: &Fake, extra: &[&str], socket: Option<&Path>| {
        let path = fake.dir.file("response", &response);
        let mut arguments: Vec<OsString> = vec!["preview".into()];
        let mut flags = fake.flags();
        if let Some(socket) = socket {
            flags[1] = socket.into();
        }
        arguments.extend(flags);
        arguments.extend(extra.iter().map(OsString::from));
        arguments.extend(path_flag("--response", &path));
        online(&arguments, &fake.hidden())
    };

    let fake = Fake::lines(&[golden_reply("previewed")]);
    fs::set_permissions(&fake.socket, fs::Permissions::from_mode(0o666)).unwrap();
    let run = preview(&fake, &[], None);
    assert!(fake.finish().is_empty());
    assert_eq!(
        (run.code, run.stderr),
        (6, refused_path(path_problem("WrongMode")))
    );

    for (mode, problem) in [(0o1777, "SharedDirectory"), (0o777, "UnsafeDirectory")] {
        let fake = Fake::lines(&[golden_reply("previewed")]);
        // The response file first: the directory is then opened to all.
        let path = fake.dir.file("response", &response);
        fs::set_permissions(&fake.dir.0, fs::Permissions::from_mode(mode)).unwrap();
        let mut arguments: Vec<OsString> = vec!["preview".into()];
        arguments.extend(fake.flags());
        arguments.extend(path_flag("--response", &path));
        let run = online(&arguments, &fake.hidden());
        fs::set_permissions(&fake.dir.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(fake.finish().is_empty(), "{problem}");
        assert_eq!(
            (run.code, run.stderr),
            (6, refused_path(path_problem(problem))),
            "{problem}"
        );
    }

    let fake = Fake::lines(&[golden_reply("previewed")]);
    let missing = fake.dir.0.join("absent");
    let file = fake.dir.file("file", b"");
    for (socket, problem) in [(&missing, "Missing"), (&file, "NotASocket")] {
        let run = preview(&fake, &[], Some(socket));
        assert_eq!(
            (run.code, run.stderr),
            (6, refused_path(path_problem(problem))),
            "{problem}"
        );
    }
    assert!(fake.finish().is_empty());

    // Another expected owner, and root alone trusted with the directories:
    // refused or not as the library decides for this user and tree.
    for (uid_offset, trust) in [(1, "service-or-root"), (0, "root-only")] {
        let fake = Fake::lines(&[golden_reply("previewed")]);
        let owner = fake.dir.owner().wrapping_add(uid_offset);
        let expected = check_socket(
            &fake.socket,
            &SocketExpectations {
                owner_uid: owner,
                ancestors: if trust == "root-only" {
                    AncestorTrust::RootOnly
                } else {
                    AncestorTrust::ServiceOrRoot
                },
            },
        );
        let path = fake.dir.file("response", &response);
        let mut arguments: Vec<OsString> = vec!["preview".into()];
        let mut flags = fake.flags();
        flags[3] = owner.to_string().into();
        arguments.extend(flags);
        arguments.extend(["--trust-ancestors", trust].map(OsString::from));
        arguments.extend(path_flag("--response", &path));
        let run = online(&arguments, &fake.hidden());
        let received = fake.finish();
        match expected {
            Ok(_) => {
                assert_eq!(received, [golden_request("preview")], "{trust}");
                assert_eq!(run.code, 0, "{trust}: {run:?}");
            }
            Err(err) => {
                assert!(received.is_empty(), "{trust}");
                assert_eq!((run.code, run.stderr), (6, refused_path(err)), "{trust}");
            }
        }
    }
}

/// The fixed text of the library's `PathProblem` named `name`, read from a
/// tree that has it (so the test does not copy the library's wording).
fn path_problem(name: &str) -> String {
    let dir = Private::new();
    let socket = dir.0.join("s");
    let _listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let mut path = socket.clone();
    match name {
        "WrongMode" => fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap(),
        "SharedDirectory" => {
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o1777)).unwrap();
        }
        "UnsafeDirectory" => {
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap()
        }
        "Missing" => path = dir.0.join("absent"),
        "NotASocket" => path = dir.file("file", b""),
        other => panic!("no tree for {other}"),
    }
    let refused = check_socket(
        &path,
        &SocketExpectations {
            owner_uid: dir.owner(),
            ancestors: AncestorTrust::ServiceOrRoot,
        },
    )
    .expect_err(name);
    assert_eq!(format!("{:?}", refused.problem()), name);
    refused.to_string()
}

/// A socket that passes the checks but has no listener (a stale socket
/// file of mode 0600): the connect is refused, exit 6, its kind named.
#[test]
fn a_connection_refused_is_exit_6() {
    let dir = Private::new();
    let socket = dir.0.join("s");
    drop(UnixListener::bind(&socket).unwrap());
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let response = dir.file("response", &golden_response());
    let mut arguments: Vec<OsString> = vec!["preview".into(), "--socket".into()];
    arguments.push(socket.clone().into());
    arguments.extend(["--service-uid".into(), dir.owner().to_string().into()]);
    arguments.extend(path_flag("--response", &response));
    let run = online(&arguments, &[socket.display().to_string()]);
    assert_eq!(
        run,
        Run {
            code: 6,
            stdout: String::new(),
            stderr: format!(
                "skyoauth-operator: the request was not sent: no connection to the local \
                 transport could be made ({})\n{UNCHANGED_NEXT}",
                io::ErrorKind::ConnectionRefused
            ),
        }
    );
}

/// Refused before any connection, exit 1: a response whose signature is
/// not 64 bytes (63 or 65; never padded or cut), and a request over
/// 64 KiB (a response artifact within its own limit whose `preview` line,
/// one member longer, is not).
#[test]
fn inputs_refused_before_any_connection_are_exit_1() {
    let length = "skyoauth-operator: refused (Length): the signature is not 64 bytes\n";
    let too_large = "skyoauth-operator: refused (TooLarge): the request was not sent: the request \
                     line is larger than 64 KiB\n";
    // An operation ID that makes the artifact exactly 64 KiB.
    let long_id = "o".repeat(64 * 1024 - 163);
    let cases = [
        (response_artifact(OPERATION, &SIGNATURE[..126]), length),
        (
            response_artifact(OPERATION, &format!("{SIGNATURE}00")),
            length,
        ),
        (response_artifact(&long_id, SIGNATURE), too_large),
    ];
    assert_eq!(cases[2].0.len(), 64 * 1024);
    for (artifact, message) in cases {
        let fake = Fake::lines(&[golden_reply("previewed")]);
        let response = fake.dir.file("response", &artifact);
        let run = fake.run("preview", &path_flag("--response", &response));
        assert!(fake.finish().is_empty(), "{message}");
        assert_eq!(
            run,
            Run {
                code: 1,
                stdout: String::new(),
                stderr: message.to_owned(),
            }
        );
    }
}

/// The file errors of the online commands: exit 3, the flag and the kind,
/// and no connection. A missing `--response`, `--challenge` or
/// `--credential-spki`, an empty key file or one over 4096 bytes; and an
/// artifact that is not one, exit 1, also with no connection.
#[test]
fn file_errors_are_exit_3_with_nothing_sent() {
    let not_found = io::ErrorKind::NotFound;
    let fake = Fake::lines(&[golden_reply("previewed")]);
    let missing = fake.dir.0.join("missing");
    let empty = fake.dir.file("empty", b"");
    let large = fake.dir.file("large", &vec![0x30; 4097]);
    let malformed = fake.dir.file("malformed", b"{}\n");
    let refusal = fake.dir.file("refusal", &golden_reply("error_conflict"));
    let key_flags = |spki: &Path| {
        let mut rest: Vec<OsString> = ["--reconcile", "bootstrap", "--instance-id", INSTANCE]
            .map(OsString::from)
            .to_vec();
        rest.extend(path_flag("--credential-spki", spki));
        rest.extend(["--trust-anchor", ANCHOR, "--recovery-key", RECOVERY_KEY].map(OsString::from));
        rest
    };
    let cases: Vec<(&str, Vec<OsString>, i32, String)> = vec![
        (
            "preview",
            path_flag("--response", &missing),
            3,
            format!("--response: the file cannot be read ({not_found})"),
        ),
        (
            "status",
            path_flag("--challenge", &missing),
            3,
            format!("--challenge: the file cannot be read ({not_found})"),
        ),
        (
            "status",
            path_flag("--credential-spki", &missing),
            3,
            format!("--credential-spki: the file cannot be read ({not_found})"),
        ),
        (
            "status",
            path_flag("--credential-spki", &empty),
            3,
            "--credential-spki: the file is empty".into(),
        ),
        (
            "status",
            key_flags(&large),
            3,
            "--credential-spki: the file is larger than 4096 bytes".into(),
        ),
        (
            "status",
            path_flag("--response", &fake.dir.0),
            3,
            "--response: not a regular file".into(),
        ),
        (
            "preview",
            path_flag("--response", &malformed),
            1,
            "the response artifact is malformed: it is not {\"operation_id\":\"...\",\
             \"signature\":\"...\"}"
                .into(),
        ),
        (
            "status",
            path_flag("--challenge", &refusal),
            1,
            "the challenge artifact is a refusal of the local transport, not a challenge \
             (conflict: the stored state refuses the request)"
                .into(),
        ),
    ];
    for (command, rest, code, message) in cases {
        let run = fake.run(command, &rest);
        assert_eq!(
            run,
            Run {
                code,
                stdout: String::new(),
                stderr: format!("skyoauth-operator: {message}\n"),
            },
            "{command} {message}"
        );
    }
    assert!(fake.finish().is_empty());
}

/// The defaults of the waits that the help states are the library's.
#[test]
fn the_default_waits_are_the_librarys() {
    assert_eq!(DEFAULT_TOTAL_WAIT, Duration::from_secs(100));
    assert_eq!(DEFAULT_IDLE_WAIT, Duration::from_secs(10));
    let help = online(&["--help"], &[]);
    assert!(
        help.stdout
            .contains("--total-wait (default 100) and --idle-wait (default 10)"),
        "{help:?}"
    );
}

/// Nothing an online run prints names a value given on the command line:
/// a refused value is named by its flag, and a socket path, a refused one
/// or one the run reached, is never printed (`online` checks every run for
/// the paths; here also a path with a sentinel in it).
#[test]
fn no_value_given_is_printed() {
    let fake = Fake::lines(&[golden_reply("status_nothing")]);
    let sentinel = fake.dir.0.join("SENTINEL-socket");
    let mut arguments: Vec<OsString> = vec!["status".into()];
    let mut flags = fake.flags();
    flags[1] = sentinel.into();
    arguments.extend(flags);
    let run = online(&arguments, &fake.hidden());
    assert_eq!(run.code, 6, "{run:?}");
    assert!(!run.stderr.contains("SENTINEL"), "{run:?}");
    assert!(fake.finish().is_empty());
}
