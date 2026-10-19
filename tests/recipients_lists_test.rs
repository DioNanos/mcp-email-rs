//! Recipient lists end to end: drafts keep Cc/Bcc, the SMTP envelope
//! carries to+cc+bcc while DATA never carries Bcc, an invalid entry
//! anywhere in the list produces ZERO side effects, and an SMTP failure
//! — whose server text may quote the refused recipient, Bcc included —
//! reaches the client and the log as a classified severity+code only,
//! never as raw server text.
//!
//! Fake servers, in-process, loopback only — no real IMAP/SMTP server is
//! ever contacted and no mail is ever sent:
//!
//! - fake IMAP (TLS, fixture certificate) modeled on
//!   `tests/update_draft_imap_test.rs`, extended to record the APPENDed
//!   literal bytes so the tests assert on the REAL raw draft;
//! - fake SMTP (plain TCP) exercised through lettre's real async SMTP
//!   client (`builder_dangerous`: the only plaintext transport lettre
//!   offers — the production `relay`/`starttls_relay` constructors both
//!   enforce verified TLS, which a loopback fake cannot present).
//!
//! The envelope/DATA properties under test belong to the `Message` and
//! to lettre's send path (`send_raw(message.envelope(), formatted())`),
//! not to the transport constructor, so the plaintext transport verifies
//! exactly the behavior under test; the same holds for the refusal
//! classification tests, which feed the REAL `smtp::Error` produced by
//! lettre to the exact classifier used by the send path.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::{TcpListener, TcpStream};

use rustls::pki_types::pem::PemObject;

use mcp_email_rs::config::{AuthMechanism, EmailConfig, SaveSentMode};
use mcp_email_rs::server::{EmailServer, SendEmailParams};

type Shared<T> = Arc<Mutex<T>>;

const CERT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls-test-cert.pem"
);
const KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/tls-test-key.pem"
);

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_file_iter(CERT)
        .expect("fixture cert leggibile")
        .collect::<Result<_, _>>()
        .expect("fixture cert valido");
    let key = rustls::pki_types::PrivateKeyDer::pem_file_iter(KEY)
        .expect("fixture key leggibile")
        .next()
        .expect("fixture key non vuota")
        .expect("fixture key valida");
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server TLS configurabile");
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

// ── Fake SMTP (plain TCP, loopback) ─────────────────────────────────

#[derive(Default)]
struct SmtpCapture {
    mail_from: Mutex<Vec<String>>,
    rcpt_to: Mutex<Vec<String>>,
    data: Mutex<Vec<u8>>,
}

/// Scripted refusal: when a command line starts with `on_command`
/// (uppercase, e.g. `EHLO` or `RCPT TO:`), the fake replies
/// `{code} {text}` instead of the permissive 250. Used to make lettre
/// produce REAL 4xx/5xx errors whose text quotes a recipient address.
#[derive(Clone)]
struct ScriptedRefusal {
    on_command: &'static str,
    code: u16,
    text: String,
}

struct FakeSmtp {
    port: u16,
    capture: Shared<SmtpCapture>,
    connections: Arc<AtomicUsize>,
}

impl FakeSmtp {
    async fn start() -> Self {
        Self::start_with_refusal(None).await
    }

    async fn start_with_refusal(refusal: Option<ScriptedRefusal>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake smtp");
        let port = listener.local_addr().expect("local addr").port();
        let capture: Shared<SmtpCapture> = Arc::new(Mutex::new(SmtpCapture::default()));
        let connections = Arc::new(AtomicUsize::new(0));
        tokio::spawn(fake_smtp_loop(
            listener,
            capture.clone(),
            connections.clone(),
            refusal,
        ));
        FakeSmtp {
            port,
            capture,
            connections,
        }
    }

    fn rcpt_to(&self) -> Vec<String> {
        self.capture.lock().unwrap().rcpt_to.lock().unwrap().clone()
    }
    fn mail_from(&self) -> Vec<String> {
        self.capture
            .lock()
            .unwrap()
            .mail_from
            .lock()
            .unwrap()
            .clone()
    }
    fn data(&self) -> Vec<u8> {
        self.capture.lock().unwrap().data.lock().unwrap().clone()
    }
    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

async fn smtp_write(stream: &mut TcpStream, line: &str) {
    let _ = stream.write_all(format!("{line}\r\n").as_bytes()).await;
}

async fn fake_smtp_loop(
    listener: TcpListener,
    capture: Shared<SmtpCapture>,
    connections: Arc<AtomicUsize>,
    refusal: Option<ScriptedRefusal>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        connections.fetch_add(1, Ordering::SeqCst);
        let capture = capture.clone();
        let refusal = refusal.clone();
        tokio::spawn(async move {
            if handle_smtp_conn(stream, capture, refusal).await.is_err() {
                return;
            }
        });
    }
}

/// Minimal ESMTP conversation: EHLO / MAIL FROM / RCPT TO / DATA / QUIT.
/// Unknown commands get a permissive 250 so lettre never deadlocks.
async fn handle_smtp_conn(
    stream: TcpStream,
    capture: Shared<SmtpCapture>,
    refusal: Option<ScriptedRefusal>,
) -> std::io::Result<()> {
    let mut stream = stream;
    smtp_write(&mut stream, "220 fake-smtp ESMTP ready").await;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let mut lines = AsyncBufReader::new(&mut rd);
    loop {
        let mut line = String::new();
        if lines.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        let upper = line.to_uppercase();
        if let Some(refusal) = &refusal
            && upper.starts_with(refusal.on_command)
        {
            let _ = wr
                .write_all(format!("{} {}\r\n", refusal.code, refusal.text).as_bytes())
                .await;
            continue;
        }
        if upper.starts_with("EHLO") || upper.starts_with("HELO") {
            let _ = wr.write_all(b"250 fake-smtp greets you\r\n").await;
        } else if upper.starts_with("MAIL FROM:") {
            capture
                .lock()
                .unwrap()
                .mail_from
                .lock()
                .unwrap()
                .push(extract_address(&line));
            let _ = wr.write_all(b"250 ok\r\n").await;
        } else if upper.starts_with("RCPT TO:") {
            capture
                .lock()
                .unwrap()
                .rcpt_to
                .lock()
                .unwrap()
                .push(extract_address(&line));
            let _ = wr.write_all(b"250 ok\r\n").await;
        } else if upper.starts_with("DATA") {
            let _ = wr.write_all(b"354 end with .\r\n").await;
            let mut data: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let n = lines.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                data.extend_from_slice(&chunk[..n]);
                if data.ends_with(b"\r\n.\r\n") {
                    data.truncate(data.len() - 5);
                    capture.lock().unwrap().data.lock().unwrap().extend(&data);
                    let _ = wr.write_all(b"250 ok\r\n").await;
                    break;
                }
            }
        } else if upper.starts_with("QUIT") {
            let _ = wr.write_all(b"221 bye\r\n").await;
            return Ok(());
        } else {
            // RSET, NOOP, AUTH (never requested: no credentials), ...
            let _ = wr.write_all(b"250 ok\r\n").await;
        }
    }
}

/// `RCPT TO:<addr> PARAM=x` → `addr`.
fn extract_address(line: &str) -> String {
    let start = line.find('<').map(|i| i + 1).unwrap_or(0);
    let end = line[start..]
        .find('>')
        .map(|i| start + i)
        .unwrap_or(line.len());
    line[start..end].to_string()
}

// ── Fake IMAP (TLS, modeled on update_draft_imap_test) ─────────────

#[derive(Clone, Debug)]
struct FakeMsg {
    uid: u32,
    deleted: bool,
}

#[derive(Clone, Debug, Default)]
struct MailboxState {
    messages: Vec<FakeMsg>,
    uidnext: u32,
}

impl MailboxState {
    fn with_old_and_stale_deleted() -> Self {
        Self {
            messages: vec![
                FakeMsg {
                    uid: 1,
                    deleted: false,
                },
                FakeMsg {
                    uid: 2,
                    deleted: true,
                },
            ],
            uidnext: 3,
        }
    }
    fn exists(&self, uid: u32) -> bool {
        self.messages.iter().any(|m| m.uid == uid)
    }
    fn is_deleted(&self, uid: u32) -> bool {
        self.messages
            .iter()
            .find(|m| m.uid == uid)
            .map(|m| m.deleted)
            .unwrap_or(false)
    }
}

async fn imap_respond(wr: &mut (impl tokio::io::AsyncWrite + Unpin), r: String) {
    let _ = wr.write_all(format!("{r}\r\n").as_bytes()).await;
}

async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    commands: Shared<Vec<String>>,
    state: Shared<MailboxState>,
    appended: Shared<Vec<Vec<u8>>>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
        let commands = commands.clone();
        let state = state.clone();
        let appended = appended.clone();
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = stream
                .write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS] fake server\r\n")
                .await;
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut lines = AsyncBufReader::new(&mut rd);
            loop {
                let mut line = String::new();
                match lines.read_line(&mut line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                };
                commands.lock().unwrap().push(line.clone());
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("").to_string();
                let cmd = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let upper = format!("{cmd} {rest}").to_uppercase();
                let toks: Vec<&str> = line.split_whitespace().collect();

                if upper.starts_with("LOGIN") || upper.starts_with("NOOP") {
                    imap_respond(&mut wr, format!("{tag} OK")).await;
                    continue;
                }
                if upper.starts_with("CAPABILITY") {
                    imap_respond(&mut wr, "* CAPABILITY IMAP4rev1 AUTH=PLAIN UIDPLUS".into()).await;
                    imap_respond(&mut wr, format!("{tag} OK")).await;
                    continue;
                }
                if upper.starts_with("LIST") {
                    imap_respond(&mut wr, "* LIST (\\HasNoChildren) \"/\" \"Drafts\"".into()).await;
                    imap_respond(&mut wr, format!("{tag} OK")).await;
                    continue;
                }
                if upper.starts_with("SELECT") {
                    let resp = {
                        let st = state.lock().unwrap();
                        format!(
                            "* {} EXISTS\r\n* 0 RECENT\r\n* FLAGS (\\Deleted)\r\n* OK [UIDVALIDITY 1] UIDs valid\r\n* OK [UIDNEXT {}] Predicted next UID\r\n{} OK [READ-WRITE] SELECT completed",
                            st.messages.len(),
                            st.uidnext,
                            tag
                        )
                    };
                    let _ = wr.write_all(format!("{resp}\r\n").as_bytes()).await;
                    continue;
                }
                if upper.starts_with("UID EXPUNGE") {
                    let target: u32 = toks
                        .iter()
                        .position(|t| t.eq_ignore_ascii_case("EXPUNGE"))
                        .and_then(|i| toks.get(i + 1))
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0);
                    let removed = {
                        let mut st = state.lock().unwrap();
                        let had = st.messages.iter().any(|m| m.uid == target && m.deleted);
                        st.messages.retain(|m| !(m.uid == target && m.deleted));
                        had
                    };
                    if removed {
                        imap_respond(&mut wr, format!("* {target} EXPUNGE")).await;
                    }
                    imap_respond(&mut wr, format!("{tag} OK UID EXPUNGE completed")).await;
                    continue;
                }
                if upper.contains("STORE") {
                    let uid: u32 = toks
                        .iter()
                        .position(|t| t.eq_ignore_ascii_case("STORE"))
                        .and_then(|i| toks.get(i + 1))
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(0);
                    let marking_deleted = upper.contains("\\DELETED");
                    {
                        let mut st = state.lock().unwrap();
                        if let Some(m) = st.messages.iter_mut().find(|m| m.uid == uid) {
                            if marking_deleted {
                                m.deleted = true;
                            }
                        }
                    }
                    imap_respond(&mut wr, format!("* {uid} FETCH (FLAGS (\\Deleted))")).await;
                    imap_respond(&mut wr, format!("{tag} OK")).await;
                    continue;
                }
                if upper.starts_with("APPEND") {
                    // Dimensione del literal "{n}".
                    let len: usize = rest
                        .rsplit('{')
                        .next()
                        .and_then(|s| s.split('}').next())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    imap_respond(&mut wr, "+ Ready for literal".into()).await;
                    let mut lit = vec![0u8; len];
                    if lines.read_exact(&mut lit).await.is_err() {
                        return;
                    }
                    let mut crlf = [0u8; 2];
                    if lines.read_exact(&mut crlf).await.is_err() {
                        return;
                    }
                    appended.lock().unwrap().push(lit);
                    let new_uid = {
                        let mut st = state.lock().unwrap();
                        let new_uid = st.uidnext;
                        st.messages.push(FakeMsg {
                            uid: new_uid,
                            deleted: false,
                        });
                        st.uidnext += 1;
                        new_uid
                    };
                    imap_respond(
                        &mut wr,
                        format!("{tag} OK [APPENDUID 1 {new_uid}] APPEND completed"),
                    )
                    .await;
                    continue;
                }
                if upper.starts_with("LOGOUT") {
                    imap_respond(&mut wr, "* BYE".into()).await;
                    imap_respond(&mut wr, format!("{tag} OK LOGOUT")).await;
                    return;
                }
                imap_respond(&mut wr, format!("{tag} OK ignored")).await;
            }
        });
    }
}

// ── Client MCP reale su stdio (come update_draft_imap_test) ────────

struct McpClient {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
    stderr_handle: Option<std::thread::JoinHandle<()>>,
    /// Everything the process LOGGED: non-JSON stdout lines (the console
    /// tracing layer writes to stdout when RUST_LOG is set) plus stderr.
    log: Shared<Vec<u8>>,
}

impl McpClient {
    fn spawn(config_path: &str, log: Shared<Vec<u8>>) -> Self {
        let drain_log = log.clone();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-email-rs"))
            .env("EMAIL_CONFIG", config_path)
            // The console tracing layer only exists when RUST_LOG is set:
            // "warn" turns the send-failure warnings on so the tests can
            // assert that the LOG lines, not just the client errors, stay
            // free of raw server text and addresses.
            .env("RUST_LOG", "warn")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("binario mcp-email-rs avviabile");
        let stdout = child.stdout.take().expect("stdout del binario");
        let stderr = child.stderr.take().expect("stderr del binario");
        let stderr_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut stderr = stderr;
            let mut chunk = [0u8; 4096];
            loop {
                match stderr.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drain_log.lock().unwrap().extend_from_slice(&chunk[..n]),
                }
            }
        });
        let mut client = McpClient {
            child,
            reader: BufReader::new(stdout),
            stderr_handle: Some(stderr_handle),
            log,
        };
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"recipients-lists-test","version":"0"}}}"#);
        let _ = client.wait_for_id(0);
        client.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        client
    }

    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().expect("stdin del binario");
        stdin
            .write_all(format!("{line}\n").as_bytes())
            .expect("scrittura su stdin");
        stdin.flush().expect("flush stdin");
    }

    fn wait_for_id(&mut self, id: u64) -> Option<serde_json::Value> {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while std::time::Instant::now() < deadline {
            let mut line = String::new();
            let n = match self.reader.read_line(&mut line) {
                Ok(n) => n,
                Err(_) => return None,
            };
            if n == 0 {
                return None;
            }
            match serde_json::from_str::<serde_json::Value>(line.trim()) {
                Ok(v) if v.get("id").and_then(|i| i.as_u64()) == Some(id) => return Some(v),
                // Non-JSON lines are console log output, not protocol:
                // keep them as the process log.
                Err(_) => self.log.lock().unwrap().extend_from_slice(line.as_bytes()),
                _ => {}
            }
        }
        None
    }

    fn call(&mut self, id: u64, name: &str, arguments: &str) -> Option<serde_json::Value> {
        let req = format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
        );
        self.send(&req);
        self.wait_for_id(id)
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        let _ = self.child.stdin.take();
        let _ = self.child.wait();
        // After the child exits the stderr pipe reaches EOF, so the drain
        // thread finishes: joining it makes the captured log complete and
        // race-free for the assertions that read it.
        if let Some(handle) = self.stderr_handle.take() {
            let _ = handle.join();
        }
    }
}

fn is_error_response(response: &serde_json::Value) -> bool {
    response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true)
}

struct Scenario {
    commands: Vec<String>,
    responses: Vec<serde_json::Value>,
    state: Shared<MailboxState>,
    appended: Vec<Vec<u8>>,
    smtp_connections: usize,
    /// Everything the server binary LOGGED (RUST_LOG=warn console lines,
    /// non-JSON, plus stderr): asserted to stay free of raw server text
    /// and addresses.
    log: String,
}

/// Ogni scenario ha i PROPRI fake IMAP e SMTP su loopback: la config del
/// binario punta a entrambi, cosi' i test "zero effetti" possono anche
/// contare le connessioni SMTP mai avvenute.
async fn run_scenario(calls: &[(&str, &str)]) -> Scenario {
    run_scenario_with_refusal(None, calls).await
}

async fn run_scenario_with_refusal(
    refusal: Option<ScriptedRefusal>,
    calls: &[(&str, &str)],
) -> Scenario {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let smtp = FakeSmtp::start_with_refusal(refusal).await;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let imap_port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    let state: Shared<MailboxState> =
        Arc::new(Mutex::new(MailboxState::with_old_and_stale_deleted()));
    let appended: Shared<Vec<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(fake_imap_loop(
        listener,
        tls_acceptor(),
        commands.clone(),
        state.clone(),
        appended.clone(),
    ));

    let smtp_port = smtp.port;
    let config_path = std::env::temp_dir().join(format!("recipients-lists-test-{imap_port}.toml"));
    std::fs::write(
        &config_path,
        format!(
            "[imap]\nhost = \"127.0.0.1\"\nport = {imap_port}\nuser = \"test@local\"\npassword = \"test\"\ntls = true\ntls_reject_unauthorized = false\nauth = \"plain\"\n\n[pool]\nmax_connections = 1\nidle_timeout_secs = 60\noperation_timeout_secs = 10\n\n[smtp]\nhost = \"127.0.0.1\"\nport = {smtp_port}\nuser = \"test@local\"\npassword = \"test\"\nstarttls = true\nfrom_address = \"agent@example.test\"\n"
        ),
    )
    .expect("config di test scrivibile");
    let config_str = config_path.to_str().unwrap().to_string();

    let calls_owned: Vec<(u64, String, String)> = calls
        .iter()
        .enumerate()
        .map(|(i, (name, args))| (i as u64 + 1, name.to_string(), args.to_string()))
        .collect();
    let responses: Shared<Vec<serde_json::Value>> = Arc::new(Mutex::new(Vec::new()));
    let responses_for_driver = responses.clone();
    let log: Shared<Vec<u8>> = Arc::new(Mutex::new(Vec::new()));
    let log_for_driver = log.clone();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let driver = std::thread::spawn(move || {
        let mut client = McpClient::spawn(&config_str, log_for_driver);
        for (id, name, args) in calls_owned {
            let resp = client.call(id, &name, &args);
            responses_for_driver
                .lock()
                .unwrap()
                .push(resp.unwrap_or_default());
        }
        drop(client);
        let _ = done_tx.blocking_send(());
    });
    let drove = tokio::time::timeout(Duration::from_secs(90), done_rx.recv()).await;
    assert!(
        drove.is_ok(),
        "driver MCP non completato entro il timeout; comandi visti dal fake: {:?}",
        commands.lock().unwrap()
    );
    let _ = driver.join();
    let _ = std::fs::remove_file(&config_path);

    // Il fake SMTP viene lasciato attivo per tutta la durata del driver:
    // il conto connessioni qui e' definitivo.
    Scenario {
        commands: commands.lock().unwrap().clone(),
        responses: responses.lock().unwrap().clone(),
        state,
        appended: appended.lock().unwrap().clone(),
        smtp_connections: smtp.connection_count(),
        log: String::from_utf8_lossy(&log.lock().unwrap()).into_owned(),
    }
}

fn destructive_commands(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| {
            let u = c.to_uppercase();
            u.contains("APPEND") || u.contains("STORE") || u.contains("EXPUNGE")
        })
        .cloned()
        .collect()
}

fn compose_config() -> EmailConfig {
    EmailConfig {
        imap_host: "imap.example.test".into(),
        imap_port: 993,
        imap_user: "agent@example.test".into(),
        imap_password: "test-password".into(),
        imap_tls: true,
        imap_tls_reject_unauthorized: true,
        imap_auth: AuthMechanism::Plain,
        imap_xoauth2_token: None,
        smtp_host: "smtp.example.test".into(),
        smtp_port: 587,
        smtp_user: "agent@example.test".into(),
        smtp_password: "test-password".into(),
        smtp_starttls: true,
        smtp_from_address: "agent@example.test".into(),
        smtp_save_sent: SaveSentMode::Always,
        smtp_allowed_from: vec!["agent@example.test".into()],
        pool_max_connections: 1,
        pool_idle_timeout_secs: 30,
        operation_timeout_secs: 30,
        attachment_dir: None,
        attachment_max_mime_bytes: mcp_email_rs::attachments::DEFAULT_MAX_MIME_BYTES,
        attachment_max_count: mcp_email_rs::attachments::DEFAULT_MAX_COUNT,
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── 1. Envelope SMTP con to+cc+bcc, DATA senza Bcc ─────────────────

/// lettre 0.11.21 verified at runtime: `builder.bcc` feeds the ENVELOPE
/// (RCPT TO for every to+cc+bcc) and the default `drop_bcc` removes the
/// Bcc header from the serialized message (DATA has To and Cc, no Bcc,
/// and no bcc address appears anywhere in the bytes).
#[tokio::test]
async fn smtp_envelope_carries_all_recipients_and_data_has_no_bcc() {
    let smtp = FakeSmtp::start().await;
    let server = EmailServer::from_config(compose_config()).expect("server");

    let message = server
        .compose_send_email(&SendEmailParams {
            to: "t1@example.test, t2@example.test".into(),
            subject: "envelope".into(),
            body: Some("corpo".into()),
            html: None,
            cc: Some("c1@example.test; c2@example.test".into()),
            bcc: Some("\"Hidden, One\" <b1@example.test>, b2@example.test".into()),
            reply_to: None,
            in_reply_to: None,
            references: None,
            from: None,
            attachments: None,
        })
        .expect("compose");

    let transport =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(smtp.port)
            .build();
    use lettre::AsyncTransport;
    transport.send(message).await.expect("send sul fake SMTP");

    // Envelope: EVERY recipient of to, cc AND bcc, in field order.
    assert_eq!(
        smtp.rcpt_to(),
        vec![
            "t1@example.test",
            "t2@example.test",
            "c1@example.test",
            "c2@example.test",
            "b1@example.test",
            "b2@example.test",
        ],
        "l'envelope deve portare to+cc+bcc"
    );
    assert_eq!(smtp.mail_from(), vec!["agent@example.test"]);

    let data = smtp.data();
    // DATA: To e Cc con TUTTI gli indirizzi, NESSUN header Bcc e nessun
    // indirizzo bcc nei byte.
    assert!(contains(&data, b"To:"), "header To nel DATA");
    assert!(contains(&data, b"t1@example.test"));
    assert!(contains(&data, b"t2@example.test"));
    assert!(contains(&data, b"Cc:"), "header Cc nel DATA");
    assert!(contains(&data, b"c1@example.test"));
    assert!(contains(&data, b"c2@example.test"));
    assert!(
        !contains(&data, b"Bcc:"),
        "nessun header Bcc nel DATA (RFC 5322 §3.6.3)"
    );
    assert!(
        !contains(&data, b"b1@example.test") && !contains(&data, b"b2@example.test"),
        "nessun indirizzo bcc nei byte del DATA"
    );
}

// ── 2. Raw della bozza con Cc e Bcc (create e update) ──────────────

#[tokio::test]
async fn create_draft_raw_keeps_cc_and_bcc_headers() {
    let scenario = run_scenario(
        &[
            (
                "create_draft",
                r#"{"to":"t1@example.test, t2@example.test","subject":"bozza cc/bcc","body":"corpo","cc":"c1@example.test; c2@example.test","bcc":"\"Nascosto, Uno\" <b1@example.test>, b2@example.test"}"#,
            ),
        ],
    )
    .await;

    assert!(
        !is_error_response(&scenario.responses[0]),
        "create_draft con liste deve riuscire: {:?}",
        scenario.responses[0]
    );
    let literals = &scenario.appended;
    assert_eq!(literals.len(), 1, "un solo APPEND atteso");
    let raw = &literals[0];
    assert!(contains(raw, b"To:"));
    assert!(contains(raw, b"t1@example.test") && contains(raw, b"t2@example.test"));
    assert!(contains(raw, b"Cc:"), "header Cc nel raw della bozza");
    assert!(contains(raw, b"c1@example.test") && contains(raw, b"c2@example.test"));
    assert!(
        contains(raw, b"Bcc:"),
        "header Bcc nel raw della bozza PRIVATA (resta modificabile)"
    );
    assert!(contains(raw, b"b1@example.test") && contains(raw, b"b2@example.test"));
}

#[tokio::test]
async fn update_draft_raw_keeps_cc_and_bcc_headers() {
    let scenario = run_scenario(
        &[
            (
                "update_draft",
                r#"{"uid":1,"to":"t1@example.test; t2@example.test","subject":"aggiornata","body":"corpo","cc":"c1@example.test, c2@example.test","bcc":"b1@example.test;b2@example.test"}"#,
            ),
        ],
    )
    .await;

    assert!(
        !is_error_response(&scenario.responses[0]),
        "update_draft con liste deve riuscire: {:?}",
        scenario.responses[0]
    );
    assert_eq!(scenario.appended.len(), 1, "un solo APPEND atteso");
    let raw = &scenario.appended[0];
    assert!(contains(raw, b"To:"));
    assert!(contains(raw, b"t1@example.test") && contains(raw, b"t2@example.test"));
    assert!(contains(raw, b"Cc:"));
    assert!(contains(raw, b"c1@example.test") && contains(raw, b"c2@example.test"));
    assert!(contains(raw, b"Bcc:"));
    assert!(contains(raw, b"b1@example.test") && contains(raw, b"b2@example.test"));
}

/// Sostituzione completa: cc/bcc OMESSI = header RIMOSSI dalla nuova
/// bozza (documentato nella descrizione del tool).
#[tokio::test]
async fn update_draft_omitted_cc_bcc_remove_the_headers() {
    let scenario = run_scenario(&[(
        "update_draft",
        r#"{"uid":1,"to":"t1@example.test","subject":"senza cc/bcc","body":"corpo"}"#,
    )])
    .await;

    assert!(
        !is_error_response(&scenario.responses[0]),
        "update_draft senza cc/bcc deve riuscire: {:?}",
        scenario.responses[0]
    );
    assert_eq!(scenario.appended.len(), 1);
    let raw = &scenario.appended[0];
    assert!(!contains(raw, b"Cc:"), "Cc omesso = header assente");
    assert!(!contains(raw, b"Bcc:"), "Bcc omesso = header assente");
}

// ── 3. Seconda voce invalida: ZERO effetti ─────────────────────────

#[tokio::test]
async fn invalid_second_recipient_update_draft_zero_side_effects() {
    let scenario = run_scenario(&[(
        "update_draft",
        r#"{"uid":1,"to":"ok@example.test, non-e-una-email","subject":"x","body":"x"}"#,
    )])
    .await;

    assert!(
        is_error_response(&scenario.responses[0]),
        "la seconda voce invalida deve produrre un errore: {:?}",
        scenario.responses[0]
    );
    assert!(
        destructive_commands(&scenario.commands).is_empty(),
        "nessun APPEND/STORE/EXPUNGE con lista invalida:\n{}",
        destructive_commands(&scenario.commands).join("\n")
    );
    let st = scenario.state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve esistere ancora");
    assert!(
        !st.is_deleted(1),
        "il vecchio draft non deve essere marcato"
    );
    assert!(
        scenario.appended.is_empty(),
        "nessun literal APPEND con lista invalida"
    );
    assert_eq!(
        scenario.smtp_connections, 0,
        "nessuna connessione SMTP con lista invalida"
    );
}

#[tokio::test]
async fn invalid_second_recipient_send_email_zero_side_effects() {
    let scenario = run_scenario(
        &[
            (
                "send_email",
                r#"{"to":"ok@example.test; non-e-una-email","subject":"x","body":"x","cc":"c@example.test","bcc":"b@example.test"}"#,
            ),
        ],
    )
    .await;

    assert!(
        is_error_response(&scenario.responses[0]),
        "la seconda voce invalida deve produrre un errore: {:?}",
        scenario.responses[0]
    );
    assert_eq!(
        scenario.smtp_connections, 0,
        "nessuna connessione SMTP: la validazione della lista precede il transport"
    );
    assert!(
        scenario.commands.is_empty(),
        "nessun comando IMAP con lista invalida: {:?}",
        scenario.commands
    );
}

// ── 4. Rifiuti SMTP: classificati, mai testo grezzo né indirizzi ────

/// The fake's refusal text quotes a Bcc recipient: lettre keeps the raw
/// server text in the error Display (the leak vector is REAL), while the
/// classifier used by send_email keeps severity and code only.
#[tokio::test]
async fn smtp_transient_450_is_classified_without_raw_text_or_addresses() {
    let refusal = ScriptedRefusal {
        on_command: "RCPT TO:",
        code: 450,
        text: "4.3.2 temporary refusal: recipient policy failed for hidden-bcc@example.test".into(),
    };
    let smtp = FakeSmtp::start_with_refusal(Some(refusal)).await;
    let server = EmailServer::from_config(compose_config()).expect("server");

    let message = server
        .compose_send_email(&SendEmailParams {
            to: "t1@example.test".into(),
            subject: "refusal".into(),
            body: Some("corpo".into()),
            html: None,
            cc: None,
            bcc: Some("hidden-bcc@example.test".into()),
            reply_to: None,
            in_reply_to: None,
            references: None,
            from: None,
            attachments: None,
        })
        .expect("compose");

    let transport =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(smtp.port)
            .build();
    use lettre::AsyncTransport;
    let err = transport
        .send(message)
        .await
        .expect_err("il fake rifiuta con 450");
    let raw = err.to_string();

    // Il vettore esiste davvero: il testo grezzo del server, indirizzo Bcc
    // compreso, è nel Display dell'errore lettre.
    assert!(
        raw.contains("hidden-bcc@example.test"),
        "il fake deve ripetere il destinatario nel testo grezzo: {raw}"
    );

    // Il classificatore REALE usato da send_email: severità e codice, niente
    // testo del server, niente indirizzi.
    let classified = mcp_email_rs::server::classify_smtp_send_failure(&err);
    assert_eq!(classified, "smtp transient 450", "classificazione 450");
    for emitted in [
        format!("SMTP send failed: {classified}"),
        format!("SMTP send failed ({classified}); rebuilding transport and retrying once"),
    ] {
        assert!(
            !emitted.contains("hidden-bcc@example.test"),
            "nessun indirizzo nell'errore/warn: {emitted}"
        );
        assert!(
            !emitted.to_lowercase().contains("policy"),
            "nessun testo del server nell'errore/warn: {emitted}"
        );
    }
    assert!(smtp.connection_count() >= 1, "una conversazione è avvenuta");
}

#[tokio::test]
async fn smtp_permanent_550_is_classified_without_raw_text_or_addresses() {
    let refusal = ScriptedRefusal {
        on_command: "RCPT TO:",
        code: 550,
        text: "5.7.1 mailbox unavailable: no relay for hidden-bcc@example.test".into(),
    };
    let smtp = FakeSmtp::start_with_refusal(Some(refusal)).await;
    let server = EmailServer::from_config(compose_config()).expect("server");

    let message = server
        .compose_send_email(&SendEmailParams {
            to: "t1@example.test".into(),
            subject: "refusal".into(),
            body: Some("corpo".into()),
            html: None,
            cc: None,
            bcc: Some("hidden-bcc@example.test".into()),
            reply_to: None,
            in_reply_to: None,
            references: None,
            from: None,
            attachments: None,
        })
        .expect("compose");

    let transport =
        lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::builder_dangerous("127.0.0.1")
            .port(smtp.port)
            .build();
    use lettre::AsyncTransport;
    let err = transport
        .send(message)
        .await
        .expect_err("il fake rifiuta con 550");
    let raw = err.to_string();
    assert!(
        raw.contains("hidden-bcc@example.test"),
        "il fake deve ripetere il destinatario nel testo grezzo: {raw}"
    );

    let classified = mcp_email_rs::server::classify_smtp_send_failure(&err);
    assert_eq!(classified, "smtp permanent 550", "classificazione 550");
    let tool_error = format!("SMTP send failed: {classified}");
    assert!(
        !tool_error.contains("hidden-bcc@example.test"),
        "nessun indirizzo nell'errore: {tool_error}"
    );
    assert!(
        !tool_error.to_lowercase().contains("relay"),
        "nessun testo del server nell'errore: {tool_error}"
    );
}

/// Full binary path: a TRANSIENT 450 refusal (on EHLO, so the verified
/// STARTTLS transport never even reaches a handshake) makes send_email
/// warn, rebuild the transport and retry once. BOTH the error returned
/// to the client and the warn lines on stderr must carry the classified
/// severity+code and must NOT carry the raw server text or the address.
#[tokio::test]
async fn send_email_transient_failure_is_classified_in_error_and_log() {
    let scenario = run_scenario_with_refusal(
        Some(ScriptedRefusal {
            on_command: "EHLO",
            code: 450,
            text: "4.3.2 greylisted: retry later for hidden-bcc@example.test".into(),
        }),
        &[(
            "send_email",
            r#"{"to":"t1@example.test","subject":"rifiuto","body":"x","bcc":"hidden-bcc@example.test"}"#,
        )],
    )
    .await;

    assert!(
        is_error_response(&scenario.responses[0]),
        "l'invio rifiutato deve produrre un errore: {:?}",
        scenario.responses[0]
    );
    let response = serde_json::to_string(&scenario.responses[0]).expect("serializzabile");
    assert!(
        !response.contains("hidden-bcc@example.test"),
        "nessun indirizzo Bcc nell'errore al client: {response}"
    );
    assert!(
        !response.to_lowercase().contains("greylisted"),
        "nessun testo del server nell'errore al client: {response}"
    );
    assert!(
        response.contains("smtp transient 450"),
        "errore classificato con severità e codice: {response}"
    );

    // Log: il warn del primo fallimento e l'eventuale retry, entrambi
    // passano dal classificatore.
    let log = &scenario.log;
    assert!(
        !log.contains("hidden-bcc@example.test"),
        "nessun indirizzo Bcc nel log: {log}"
    );
    assert!(
        !log.to_lowercase().contains("greylisted"),
        "nessun testo del server nel log: {log}"
    );
    assert!(
        log.contains("smtp transient 450"),
        "il warn è classificato: {log}"
    );
    // Il primo tentativo fallisce, il retry ri-invia: almeno due
    // connessioni SMTP verso il fake.
    assert!(
        scenario.smtp_connections >= 2,
        "warn + rebuild + retry attesi (connessioni: {})",
        scenario.smtp_connections
    );
}
