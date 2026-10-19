//! `delete_email` and `batch_delete` must not use a global expunge() that
//! removes messages marked `\Deleted` by other clients.
//!
//! A stateful IMAP fake (messages, \Deleted flags, uids), a pattern reused
//! from `tests/update_draft_imap_test.rs`. The assertions are on the server
//! state and on the wire, not on the client's bytes:
//!
//! - UIDPLUS  => a targeted UID EXPUNGE on the requested uid/set only; a
//!   second message ALREADY marked \Deleted stays intact;
//! - no UIDPLUS, others marked => NO expunge; the requested message stays
//!   marked \Deleted and the response says so; the other marked one is
//!   still there;
//! - no UIDPLUS, nobody else marked => the global expunge happens
//!   (equivalent to the targeted one) and removes only what it should.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
use tokio::net::TcpListener;

use rustls::pki_types::pem::PemObject;

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
    fn normal(uids: &[u32]) -> Self {
        Self {
            messages: uids
                .iter()
                .map(|u| FakeMsg { uid: *u, deleted: false })
                .collect(),
            uidnext: uids.iter().max().copied().unwrap_or(0) + 1,
        }
    }
    /// Aggiunge una mail GIA' marcata \Deleted (di un altro client).
    fn with_stale_deleted(mut self, uid: u32) -> Self {
        self.messages.push(FakeMsg { uid, deleted: true });
        self.uidnext = self.uidnext.max(uid + 1);
        self
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

#[derive(Clone)]
struct FakeConfig {
    uidplus: bool,
    /// CAPABILITY: la connessione cade prima della risposta (fallimento vero:
    /// un NO taggato non fa fallire capabilities() in async-imap).
    caps_fail: bool,
    /// UID EXPUNGE applicato ma ACK perso: connessione cade senza risposta.
    uid_expunge_loses_ack: bool,
}

fn ok(tag: &str) -> String {
    format!("{tag} OK")
}

async fn respond(wr: &mut (impl tokio::io::AsyncWrite + Unpin), r: String) {
    use tokio::io::AsyncWriteExt;
    let _ = wr.write_all(format!("{r}\r\n").as_bytes()).await;
}

async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    config: FakeConfig,
    commands: Shared<Vec<String>>,
    state: Shared<MailboxState>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
        let config = config.clone();
        let commands = commands.clone();
        let state = state.clone();
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let caps = if config.uidplus {
                "IMAP4rev1 AUTH=PLAIN UIDPLUS"
            } else {
                "IMAP4rev1 AUTH=PLAIN"
            };
            let _ = stream
                .write_all(format!("* OK [CAPABILITY {caps}] fake server\r\n").as_bytes())
                .await;
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut lines = AsyncBufReader::new(&mut rd);
            loop {
                let mut line = String::new();
                match lines.read_line(&mut line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                commands.lock().unwrap().push(line.clone());
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("").to_string();
                let cmd = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let upper = format!("{cmd} {rest}").to_uppercase();
                let toks: Vec<&str> = line.split_whitespace().collect();

                if upper.starts_with("LOGIN") || upper.starts_with("NOOP") {
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.starts_with("CAPABILITY") {
                    if config.caps_fail {
                        return;
                    }
                    respond(&mut wr, format!("* CAPABILITY {caps}")).await;
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.starts_with("LIST") {
                    respond(
                        &mut wr,
                        "* LIST (\\HasNoChildren) \"/\" \"INBOX\"".to_string(),
                    )
                    .await;
                    respond(&mut wr, ok(&tag)).await;
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
                    // Solo UIDPLUS lo supporta; un server senza risponde BAD.
                    if !config.uidplus {
                        respond(&mut wr, format!("{tag} BAD UID EXPUNGE not supported")).await;
                        continue;
                    }
                    let target_set: Vec<u32> = toks
                        .iter()
                        .position(|t| t.eq_ignore_ascii_case("EXPUNGE"))
                        .and_then(|i| toks.get(i + 1))
                        .map(|s| {
                            s.split(',')
                                .filter_map(|p| p.parse().ok())
                                .collect::<Vec<u32>>()
                        })
                        .unwrap_or_default();
                    let removed: Vec<u32> = {
                        let mut st = state.lock().unwrap();
                        let removed: Vec<u32> = st
                            .messages
                            .iter()
                            .filter(|m| m.deleted && target_set.contains(&m.uid))
                            .map(|m| m.uid)
                            .collect();
                        st.messages
                            .retain(|m| !(m.deleted && target_set.contains(&m.uid)));
                        removed
                    };
                    for uid in removed {
                        respond(&mut wr, format!("* {uid} EXPUNGE")).await;
                    }
                    if config.uid_expunge_loses_ack {
                        // Il comando E' stato applicato; la connessione cade
                        // prima della risposta taggata: esito incerto.
                        return;
                    }
                    respond(&mut wr, format!("{tag} OK UID EXPUNGE completed")).await;
                    continue;
                }
                if upper.starts_with("EXPUNGE") {
                    // expunge() GLOBALE: rimuove OGNI messaggio marcato.
                    let removed: Vec<u32> = {
                        let mut st = state.lock().unwrap();
                        let removed: Vec<u32> = st
                            .messages
                            .iter()
                            .filter(|m| m.deleted)
                            .map(|m| m.uid)
                            .collect();
                        st.messages.retain(|m| !m.deleted);
                        removed
                    };
                    for uid in removed {
                        respond(&mut wr, format!("* {uid} EXPUNGE")).await;
                    }
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.contains("SEARCH") {
                    // "UID SEARCH DELETED": quali messaggi sono marcati ORA.
                    let deleted: Vec<String> = {
                        let st = state.lock().unwrap();
                        st.messages
                            .iter()
                            .filter(|m| m.deleted)
                            .map(|m| m.uid.to_string())
                            .collect()
                    };
                    if deleted.is_empty() {
                        respond(&mut wr, "* SEARCH".to_string()).await;
                    } else {
                        respond(&mut wr, format!("* SEARCH {}", deleted.join(" "))).await;
                    }
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.contains("STORE") {
                    // L'uid set dopo STORE puo' essere "1" o "1,2".
                    let uid_set: Vec<u32> = toks
                        .iter()
                        .position(|t| t.eq_ignore_ascii_case("STORE"))
                        .and_then(|i| toks.get(i + 1))
                        .map(|s| {
                            s.split(',')
                                .filter_map(|p| p.parse().ok())
                                .collect::<Vec<u32>>()
                        })
                        .unwrap_or_default();
                    let marking_deleted = upper.contains("\\DELETED");
                    {
                        let mut st = state.lock().unwrap();
                        for m in st.messages.iter_mut() {
                            if marking_deleted && uid_set.contains(&m.uid) {
                                m.deleted = true;
                            }
                        }
                    }
                    for uid in &uid_set {
                        respond(&mut wr, format!("* {uid} FETCH (FLAGS (\\Deleted))")).await;
                    }
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.starts_with("LOGOUT") {
                    respond(&mut wr, "* BYE".to_string()).await;
                    respond(&mut wr, format!("{tag} OK LOGOUT")).await;
                    return;
                }
                respond(&mut wr, format!("{tag} OK ignored")).await;
            }
        });
    }
}

struct McpClient {
    child: Child,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpClient {
    fn spawn(config_path: &str) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-email-rs"))
            .env("EMAIL_CONFIG", config_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("binario mcp-email-rs avviabile");
        let stdout = child.stdout.take().expect("stdout del binario");
        let mut client = McpClient {
            child,
            reader: BufReader::new(stdout),
        };
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"delete-email-imap-test","version":"0"}}}"#);
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
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim())
                && v.get("id").and_then(|i| i.as_u64()) == Some(id)
            {
                return Some(v);
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
    }
}

fn tool_text(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn is_error_response(response: &serde_json::Value) -> bool {
    response.get("error").is_some() || response["result"]["isError"].as_bool() == Some(true)
}

async fn run_scenario(
    config: FakeConfig,
    init: MailboxState,
    calls: &[(&str, &str)],
) -> (Vec<String>, Vec<serde_json::Value>, Shared<MailboxState>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    let state: Shared<MailboxState> = Arc::new(Mutex::new(init));
    tokio::spawn(fake_imap_loop(
        listener,
        tls_acceptor(),
        config,
        commands.clone(),
        state.clone(),
    ));

    let config_path = std::env::temp_dir().join(format!("delete-email-imap-{}.toml", port));
    std::fs::write(
        &config_path,
        format!(
            "[imap]\nhost = \"127.0.0.1\"\nport = {port}\nuser = \"test@local\"\npassword = \"test\"\ntls = true\ntls_reject_unauthorized = false\nauth = \"plain\"\n\n[pool]\nmax_connections = 1\nidle_timeout_secs = 60\noperation_timeout_secs = 10\n"
        ),
    )
    .expect("config di test scrivibile");

    let config_str = config_path.to_str().unwrap().to_string();
    let calls_owned: Vec<(u64, String, String)> = calls
        .iter()
        .enumerate()
        .map(|(i, (name, args))| (i as u64 + 1, name.to_string(), args.to_string()))
        .collect();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let commands_for_driver = commands.clone();
    let responses: Shared<Vec<serde_json::Value>> = Arc::new(Mutex::new(Vec::new()));
    let responses_for_driver = responses.clone();
    let driver = std::thread::spawn(move || {
        let mut client = McpClient::spawn(&config_str);
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

    let commands = commands_for_driver.lock().unwrap().clone();
    let responses = responses.lock().unwrap().clone();
    (commands, responses, state)
}

fn bare_expunge_commands(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| {
            let toks: Vec<&str> = c.split_whitespace().collect();
            toks.len() >= 2 && toks[1].eq_ignore_ascii_case("EXPUNGE")
        })
        .cloned()
        .collect()
}

fn uid_expunge_commands(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| c.to_uppercase().contains("UID EXPUNGE"))
        .cloned()
        .collect()
}

fn expunge_any(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| {
            let toks: Vec<&str> = c.split_whitespace().collect();
            toks.len() >= 2
                && (toks[1].eq_ignore_ascii_case("EXPUNGE")
                    || c.to_uppercase().contains("UID EXPUNGE"))
        })
        .cloned()
        .collect()
}

/// UIDPLUS: delete_email rimuove SOLO l'uid richiesto; la seconda mail gia'
/// marcata \Deleted (uid=2, di un altro client) resta intatta.
#[tokio::test]
async fn delete_uidplus_targets_only_requested_uid() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: true, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1]).with_stale_deleted(2),
        &[("delete_email", r#"{"uid":1}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "delete_email con UIDPLUS deve riuscire: {:?}",
        responses[0]
    );
    let ue = uid_expunge_commands(&commands);
    assert_eq!(ue.len(), 1, "esattamente un UID EXPUNGE: {commands:?}");
    assert!(
        ue[0].contains("UID EXPUNGE 1"),
        "UID EXPUNGE mirato sul solo uid 1: {:?}",
        ue[0]
    );
    assert!(
        bare_expunge_commands(&commands).is_empty(),
        "nessun EXPUNGE globale: {:?}",
        bare_expunge_commands(&commands)
    );
    let st = state.lock().unwrap();
    assert!(!st.exists(1), "uid=1 deve essere stato rimosso");
    assert!(
        st.exists(2),
        "la seconda mail gia' marcata \\Deleted (uid=2) DEVE restare intatta"
    );
}

/// Senza UIDPLUS e con ALTRI messaggi marcati: nessun expunge; la mail
/// richiesta resta marcata \Deleted, la risposta lo dichiara, l'altra e' li'.
#[tokio::test]
async fn delete_no_uidplus_other_marked_no_expunge() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: false, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1]).with_stale_deleted(2),
        &[("delete_email", r#"{"uid":1}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "l'operazione si completa dichiarando la rinuncia all'expunge: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    assert!(
        text.contains("NOT EXPUNGED"),
        "la risposta deve dichiarare che NON e' stato espunto: {text}"
    );
    assert!(
        expunge_any(&commands).is_empty(),
        "nessun expunge (ne' mirato ne' globale) consentito qui: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "uid=1 deve esistere ancora");
    assert!(
        st.is_deleted(1),
        "uid=1 deve restare marcato \\Deleted (cancellazione solo logica)"
    );
    assert!(
        st.exists(2),
        "l'altra mail marcata (uid=2) deve essere ancora li'"
    );
}

/// Without UIDPLUS there is NEVER an expunge, not even when the requested
/// message is the only marked one. A SEARCH DELETED snapshot cannot close
/// the concurrency window between the snapshot and the EXPUNGE: marking +
/// a declared deferral, always.
#[tokio::test]
async fn delete_no_uidplus_only_marked_still_deferred() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: false, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1]),
        &[("delete_email", r#"{"uid":1}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "l'operazione si completa con la marcatura e la dichiarazione: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    assert!(
        text.contains("NOT EXPUNGED"),
        "la risposta deve dichiarare il rinvio: {text}"
    );
    assert!(
        expunge_any(&commands).is_empty(),
        "senza UIDPLUS nessun expunge di alcun tipo, NEANCHE se la mail e' l'unica marcata: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "uid=1 deve restare presente");
    assert!(
        st.is_deleted(1),
        "uid=1 deve restare marcato \\Deleted (espulsione differita)"
    );
}

/// UIDPLUS, batch: UID EXPUNGE mirato sull'intero set richiesto; la mail
/// gia' marcata da un altro client (uid=3) resta intatta.
#[tokio::test]
async fn batch_uidplus_targets_only_requested_set() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: true, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1, 2]).with_stale_deleted(3),
        &[("batch_delete", r#"{"uids":[1,2]}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "batch_delete con UIDPLUS deve riuscire: {:?}",
        responses[0]
    );
    let ue = uid_expunge_commands(&commands);
    assert_eq!(ue.len(), 1, "esattamente un UID EXPUNGE: {commands:?}");
    assert!(
        ue[0].contains("UID EXPUNGE 1,2"),
        "UID EXPUNGE mirato sul set richiesto 1,2: {:?}",
        ue[0]
    );
    assert!(
        bare_expunge_commands(&commands).is_empty(),
        "nessun EXPUNGE globale: {:?}",
        bare_expunge_commands(&commands)
    );
    let st = state.lock().unwrap();
    assert!(!st.exists(1) && !st.exists(2), "uid 1 e 2 devono essere rimossi");
    assert!(
        st.exists(3),
        "la mail gia' marcata \\Deleted (uid=3) DEVE restare intatta"
    );
}

/// Senza UIDPLUS, batch con altri marcati: nessun expunge, entrambe le mail
/// richieste restano marcate, la risposta lo dichiara, la terza e' li'.
#[tokio::test]
async fn batch_no_uidplus_other_marked_deferred() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: false, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1, 2]).with_stale_deleted(3),
        &[("batch_delete", r#"{"uids":[1,2]}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "l'operazione si completa dichiarando la rinuncia: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    assert!(
        text.contains("NOT EXPUNGED"),
        "la risposta deve dichiarare che NON e' stato espunto: {text}"
    );
    assert!(
        expunge_any(&commands).is_empty(),
        "nessun expunge consentito qui: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(
        st.exists(1) && st.is_deleted(1),
        "uid=1 deve restare presente e marcato"
    );
    assert!(
        st.exists(2) && st.is_deleted(2),
        "uid=2 deve restare presente e marcato"
    );
    assert!(st.exists(3), "l'altra mail marcata (uid=3) deve essere ancora li'");
}

/// Senza UIDPLUS, batch R1: non si espunge mai, nemmeno senza altri marcati.
#[tokio::test]
async fn batch_no_uidplus_only_marked_still_deferred() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: false, caps_fail: false, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1, 2]),
        &[("batch_delete", r#"{"uids":[1,2]}"#)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "l'operazione si completa con la marcatura e la dichiarazione: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    assert!(
        text.contains("NOT EXPUNGED"),
        "la risposta deve dichiarare il rinvio: {text}"
    );
    assert!(
        expunge_any(&commands).is_empty(),
        "senza UIDPLUS nessun expunge di alcun tipo, NEANCHE per un set unico marcato: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(
        st.exists(1) && st.is_deleted(1),
        "uid=1 presente e marcato"
    );
    assert!(
        st.exists(2) && st.is_deleted(2),
        "uid=2 presente e marcato"
    );
}

/// A lost UID EXPUNGE ACK on delete_email => the error declares the removal
/// UNCERTAIN (it may have been applied), NOT "not expunged".
#[tokio::test]
async fn delete_uid_expunge_ack_lost_reports_uncertain() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: true, caps_fail: false, uid_expunge_loses_ack: true },
        MailboxState::normal(&[1]).with_stale_deleted(2),
        &[("delete_email", r#"{"uid":1}"#)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "ack perso deve dare errore: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    let err_text = responses[0]
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_uppercase();
    let combined = format!("{text} {err_text}");
    assert!(
        combined.contains("UNCERTAIN") && combined.contains("MAY HAVE BEEN APPLIED"),
        "l'errore deve dichiarare la rimozione incerta: {combined}"
    );
    assert!(
        !combined.contains("NOT EXPUNGED"),
        "l'errore NON deve affermare che l'expunge non e' avvenuto: {combined}"
    );
    assert!(
        !combined.contains("EITHER WAY"),
        "vietato affermare uno stato ('remain marked either way') quando l'esito e' incerto: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(
        !st.exists(1),
        "sul server l'UID EXPUNGE E' stato applicato: uid=1 rimosso"
    );
    assert!(st.exists(2), "la seconda mail marcata (uid=2) resta intatta");
}

/// The same scenario for batch_delete with a set.
#[tokio::test]
async fn batch_uid_expunge_ack_lost_reports_uncertain() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: true, caps_fail: false, uid_expunge_loses_ack: true },
        MailboxState::normal(&[1, 2]).with_stale_deleted(3),
        &[("batch_delete", r#"{"uids":[1,2]}"#)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "ack perso deve dare errore: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    let err_text = responses[0]
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_uppercase();
    let combined = format!("{text} {err_text}");
    assert!(
        combined.contains("UNCERTAIN") && combined.contains("MAY HAVE BEEN APPLIED"),
        "l'errore deve dichiarare la rimozione incerta: {combined}"
    );
    assert!(
        !combined.contains("NOT EXPUNGED"),
        "l'errore NON deve affermare che l'expunge non e' avvenuto: {combined}"
    );
    assert!(
        !combined.contains("EITHER WAY"),
        "vietato affermare uno stato quando l'esito e' incerto: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(
        !st.exists(1) && !st.exists(2),
        "sul server l'UID EXPUNGE E' stato applicato: uid 1 e 2 rimossi"
    );
    assert!(st.exists(3), "la terza mail marcata (uid=3) resta intatta");
}

/// A capability check failing BEFORE the expunge => here "NOT expunged" is
/// true (the removal was never attempted) and must be declared.
#[tokio::test]
async fn delete_capability_fail_reports_removal_not_attempted() {
    let (commands, responses, state) = run_scenario(
        FakeConfig { uidplus: true, caps_fail: true, uid_expunge_loses_ack: false },
        MailboxState::normal(&[1]).with_stale_deleted(2),
        &[("delete_email", r#"{"uid":1}"#)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "capability fallita deve dare errore: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    let err_text = responses[0]
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_uppercase();
    let combined = format!("{text} {err_text}");
    assert!(
        combined.contains("NOT ATTEMPTED"),
        "l'errore deve dire che la rimozione non e' mai stata tentata: {combined}"
    );
    assert!(
        combined.contains("NOT EXPUNGED"),
        "qui la dichiarazione NOT expunged e' vera e richiesta: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "uid=1 deve esistere ancora");
    assert!(st.exists(2), "uid=2 resta intatto");
}
