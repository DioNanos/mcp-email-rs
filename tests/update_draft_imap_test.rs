//! The IMAP sequence of `update_draft` must not destroy.
//!
//! The fake IMAP server MODELS the Drafts folder state (messages, `\Deleted`
//! flags, uids assigned by APPEND) and the tests assert on that STATE and on
//! the wire, not on the bytes emitted by the client:
//!
//! - invalid input        => no destructive command, old draft intact;
//! - APPEND refused       => old draft intact;
//! - APPEND uncertain     => old draft intact, NO retry;
//! - success with UIDPLUS => a targeted UID EXPUNGE on the old uid ONLY, and
//!   a second draft already marked `\Deleted` stays intact;
//! - server without UIDPLUS => no global expunge, old draft preserved,
//!   declared partial substitution.
//!
//! Pattern reused from `tests/peek_read_test.rs` (TcpListener + TLS + the
//! real MCP binary driven via JSON-RPC over stdio).

use std::io::{BufRead, BufReader, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// Cartella iniziale dei test: uid 1 = bozza da aggiornare (intatta),
    /// uid 2 = seconda bozza GIA' marcata \Deleted (nessuno la deve toccare).
    fn with_old_and_stale_deleted() -> Self {
        Self {
            messages: vec![
                FakeMsg { uid: 1, deleted: false },
                FakeMsg { uid: 2, deleted: true },
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

#[derive(Clone)]
enum AppendBehavior {
    /// APPEND riuscito; `appenduid` = il server e' UIDPLUS e manda APPENDUID;
    /// `untagged_first` = il server manda un untagged (RFC 3501 §2.2.1)
    /// PRIMA della continuation: il client NON deve rifiutare.
    Ok {
        new_uid: u32,
        appenduid: bool,
        untagged_first: bool,
    },
    /// Rifiuto definito: tagged NO al comando, senza continuation.
    Reject,
    /// Continuation data, literal ricevuto, poi la connessione cade senza
    /// risposta taggata: l'esito per il client e' INCERTO.
    DropAfterLiteral,
    /// Continuation data, literal ricevuto, poi il peer resta CONNESSO e
    /// tace: il client deve dare l'esito incerto entro il timeout operativo.
    SilentAfterLiteral,
    /// Continuation data e poi il peer NON legge piu': la write del literal
    /// blocca; il client deve dare l'esito incerto entro la deadline.
    WriteBlocking,
    /// Untagged all'infinito prima della continuation, mai una continuation:
    /// la deadline complessiva deve interrompere l'operazione.
    InfiniteUntagged,
}

#[derive(Clone)]
struct FakeConfig {
    uidplus: bool,
    append: AppendBehavior,
    /// CAPABILITY risponde tagged NO (guasto dopo un append riuscito).
    caps_fail: bool,
    /// UID EXPUNGE applicato ma ACK perso: il comando viene eseguito sullo
    /// stato e la connessione cade senza risposta taggata.
    uid_expunge_loses_ack: bool,
    /// Dalla SECONDA connessione in poi: TLS accettato ma nessun greeting
    /// (login/handshake appesi: serve per la deadline sulla connect dedicata).
    silent_second_connection: bool,
}

fn ok(tag: &str) -> String {
    format!("{tag} OK")
}

async fn respond(wr: &mut (impl tokio::io::AsyncWrite + Unpin), r: String) {
    use tokio::io::AsyncWriteExt;
    let _ = wr.write_all(format!("{r}\r\n").as_bytes()).await;
}

#[allow(clippy::too_many_arguments)]
async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    config: FakeConfig,
    commands: Shared<Vec<String>>,
    state: Shared<MailboxState>,
    conn_counter: Arc<AtomicUsize>,
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
        let conn_counter = conn_counter.clone();
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let conn_n = conn_counter.fetch_add(1, Ordering::SeqCst) + 1;
            let caps = if config.uidplus {
                "IMAP4rev1 AUTH=PLAIN UIDPLUS"
            } else {
                "IMAP4rev1 AUTH=PLAIN"
            };
            if config.silent_second_connection && conn_n >= 2 {
                // TLS accettato, poi silenzio assoluto: il login del client
                // resta appeso senza greeting (scenario dedicated-connect).
                loop {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                }
            }
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
                };
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
                        // Fallimento della CAPABILITY: la connessione cade
                        // prima della risposta. (Un NO/BAD taggato non fa
                        // fallire capabilities() nella crate: verrebbe
                        // interpretato come "nessuna capability".)
                        return;
                    }
                    respond(&mut wr, format!("* CAPABILITY {caps}")).await;
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.starts_with("LIST") {
                    respond(
                        &mut wr,
                        "* LIST (\\HasNoChildren) \"/\" \"Drafts\"".to_string(),
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
                    // Solo UIDPLUS supporta UID EXPUNGE: un server senza lo
                    // rifiuterebbe. Il fake modella entrambi i comportamenti.
                    if !config.uidplus {
                        respond(&mut wr, format!("{tag} BAD UID EXPUNGE not supported")).await;
                        continue;
                    }
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
                        respond(&mut wr, format!("* {target} EXPUNGE")).await;
                    }
                    if config.uid_expunge_loses_ack {
                        // Il comando E' stato applicato (lo stato sopra), ma
                        // la connessione cade PRIMA della risposta taggata:
                        // per il client l'esito della rimozione e' incerto.
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
                if upper.contains("STORE") {
                    // "UID STORE <uid> +FLAGS (\Deleted)" (o STORE senza UID).
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
                    respond(&mut wr, format!("* {uid} FETCH (FLAGS (\\Deleted))")).await;
                    respond(&mut wr, ok(&tag)).await;
                    continue;
                }
                if upper.starts_with("APPEND") {
                    // Estrai la dimensione del literal "{n}".
                    let len: usize = rest
                        .rsplit('{')
                        .next()
                        .and_then(|s| s.split('}').next())
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    match config.append {
                        AppendBehavior::Reject => {
                            respond(&mut wr, format!("{tag} NO APPEND failed")).await;
                        }
                        AppendBehavior::Ok {
                            new_uid,
                            appenduid,
                            untagged_first,
                        } => {
                            if untagged_first {
                                // RFC 3501 §2.2.1: untagged legittimo PRIMA
                                // della continuation.
                                respond(&mut wr, "* 3 EXISTS".to_string()).await;
                            }
                            respond(&mut wr, "+ Ready for literal".to_string()).await;
                            let mut lit = vec![0u8; len];
                            if lines.read_exact(&mut lit).await.is_err() {
                                return;
                            }
                            let mut crlf = [0u8; 2];
                            if lines.read_exact(&mut crlf).await.is_err() {
                                return;
                            }
                            {
                                let mut st = state.lock().unwrap();
                                st.messages.push(FakeMsg { uid: new_uid, deleted: false });
                                st.uidnext = st.uidnext.max(new_uid + 1);
                            }
                            if appenduid {
                                respond(
                                    &mut wr,
                                    format!("{tag} OK [APPENDUID 1 {new_uid}] APPEND completed"),
                                )
                                .await;
                            } else {
                                respond(&mut wr, format!("{tag} OK APPEND completed")).await;
                            }
                        }
                        AppendBehavior::DropAfterLiteral => {
                            respond(&mut wr, "+ Ready for literal".to_string()).await;
                            let mut lit = vec![0u8; len];
                            if lines.read_exact(&mut lit).await.is_err() {
                                return;
                            }
                            let mut crlf = [0u8; 2];
                            if lines.read_exact(&mut crlf).await.is_err() {
                                return;
                            }
                            // Il literal E' arrivato: il server potrebbe averlo
                            // salvato. La connessione cade senza risposta
                            // taggata: per il client l'esito e' INCERTO.
                            return;
                        }
                        AppendBehavior::WriteBlocking => {
                            respond(&mut wr, "+ Ready for literal".to_string()).await;
                            // Il peer smette di CONSUMARE il socket: non legge
                            // il literal. La write del client riempie i buffer
                            // TCP e poi blocca: serve un literal molto grande.
                            loop {
                                tokio::time::sleep(Duration::from_secs(3600)).await;
                            }
                        }
                        AppendBehavior::InfiniteUntagged => {
                            // Untagged senza fine, mai una continuation.
                            loop {
                                respond(&mut wr, "* 1 EXISTS".to_string()).await;
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                        AppendBehavior::SilentAfterLiteral => {
                            respond(&mut wr, "+ Ready for literal".to_string()).await;
                            let mut lit = vec![0u8; len];
                            if lines.read_exact(&mut lit).await.is_err() {
                                return;
                            }
                            let mut crlf = [0u8; 2];
                            if lines.read_exact(&mut crlf).await.is_err() {
                                return;
                            }
                            // Il peer resta CONNESSO ma tace per sempre: il
                            // client deve produrre l'esito incerto entro il
                            // suo timeout operativo, non attendere all'infinito.
                            loop {
                                tokio::time::sleep(Duration::from_secs(3600)).await;
                            }
                        }
                    }
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
    fn spawn(config_path: &str, extra_env: &[(&str, &str)]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-email-rs"))
            .env("EMAIL_CONFIG", config_path)
            .envs(extra_env.iter().map(|(k, v)| (*k, *v)))
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
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"update-draft-imap-test","version":"0"}}}"#);
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

/// Un errore MCP arriva come oggetto JSON-RPC `error` (McpError dell'handler)
/// oppure come result con isError=true.
fn is_error_response(response: &serde_json::Value) -> bool {
    response.get("error").is_some()
        || response["result"]["isError"].as_bool() == Some(true)
}

async fn run_scenario(
    config: FakeConfig,
    extra_env: &[(&str, &str)],
    calls: &[(&str, &str)],
) -> (Vec<String>, Vec<serde_json::Value>, Shared<MailboxState>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    let state: Shared<MailboxState> =
        Arc::new(Mutex::new(MailboxState::with_old_and_stale_deleted()));
    let conn_counter: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    tokio::spawn(fake_imap_loop(
        listener,
        tls_acceptor(),
        config,
        commands.clone(),
        state.clone(),
        conn_counter.clone(),
    ));

    let config_path = std::env::temp_dir().join(format!("update-draft-imap-{}.toml", port));
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
    let extra_env_owned: Vec<(String, String)> = extra_env
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let driver = std::thread::spawn(move || {
        let extra_env: Vec<(&str, &str)> = extra_env_owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let mut client = McpClient::spawn(&config_str, &extra_env);
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

const VALID_CALL: &str =
    r#"{"uid":1,"to":"dest@example.com","subject":"aggiornata","body":"nuovo corpo"}"#;
const INVALID_CALL: &str =
    r#"{"uid":1,"to":"non-e-una-email","subject":"aggiornata","body":"nuovo corpo"}"#;

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

fn expunge_commands(commands: &[String]) -> Vec<String> {
    commands
        .iter()
        .filter(|c| {
            let toks: Vec<&str> = c.split_whitespace().collect();
            toks.len() >= 2 && toks[1].eq_ignore_ascii_case("EXPUNGE")
        })
        .cloned()
        .collect()
}

/// 1. Input invalido: la validazione AVVIENE prima di ogni operazione
///    distruttiva. Il vecchio draft e' ancora lì, non e' neanche marcato.
#[tokio::test]
async fn invalid_input_keeps_old_draft_untouched() {
    let (commands, responses, state) =
        run_scenario(
            FakeConfig { uidplus: true, append: AppendBehavior::Ok { new_uid: 3, appenduid: true, untagged_first: false }, caps_fail: false, uid_expunge_loses_ack: false, silent_second_connection: false },
            &[],
            &[("update_draft", INVALID_CALL)],
        )
        .await;

    assert!(
        is_error_response(&responses[0]),
        "un input invalido deve produrre un errore: {:?}", responses[0]
    );
    let destructive = destructive_commands(&commands);
    assert!(
        destructive.is_empty(),
        "con input invalido NON deve partire nessun comando APPEND/STORE/EXPUNGE:\n{}",
        destructive.join("\n")
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve esistere ancora");
    assert!(!st.is_deleted(1), "il vecchio draft uid=1 non deve essere marcato \\Deleted");
}

/// 2. APPEND rifiutato dal server: fallimento DEFINITO prima di ogni passo
///    distruttivo. Il vecchio draft resta esattamente com'era.
#[tokio::test]
async fn append_failure_keeps_old_draft() {
    let (commands, responses, state) =
        run_scenario(
            FakeConfig { uidplus: true, append: AppendBehavior::Reject, caps_fail: false, uid_expunge_loses_ack: false, silent_second_connection: false },
            &[],
            &[("update_draft", VALID_CALL)],
        )
        .await;

    assert!(
        is_error_response(&responses[0]),
        "un APPEND rifiutato deve produrre un errore: {:?}", responses[0]
    );
    assert!(
        commands.iter().any(|c| c.to_uppercase().contains("APPEND")),
        "l'APPEND deve essere stato tentato: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve esistere ancora");
    assert!(!st.is_deleted(1), "il vecchio draft uid=1 non deve essere marcato \\Deleted");
    assert!(
        !commands.iter().any(|c| c.to_uppercase().contains("STORE")),
        "nessun UID STORE prima di un APPEND riuscito: {commands:?}"
    );
    assert!(
        expunge_commands(&commands).is_empty(),
        "nessun EXPUNGE prima di un APPEND riuscito: {commands:?}"
    );
}

/// 3. APPEND incerto (la connessione cade dopo il literal): errore che
///    DICE che l'esito e' incerto, vecchio intatto, NESSUN retry.
#[tokio::test]
async fn append_uncertain_keeps_old_draft_no_retry() {
    let (commands, responses, state) =
        run_scenario(
            FakeConfig { uidplus: true, append: AppendBehavior::DropAfterLiteral, caps_fail: false, uid_expunge_loses_ack: false, silent_second_connection: false },
            &[],
            &[("update_draft", VALID_CALL)],
        )
        .await;

    assert!(
        is_error_response(&responses[0]),
        "un APPEND con esito incerto deve produrre un errore: {:?}", responses[0]
    );
    let text = tool_text(&responses[0]).to_uppercase();
    let err_text = responses[0]
        .pointer("/error/message")
        .and_then(|m| m.as_str())
        .unwrap_or_default()
        .to_uppercase();
    let combined = format!("{text} {err_text}");
    assert!(
        combined.contains("UNCERTAIN"),
        "l'errore deve dichiarare l'esito INCERTO: {combined}"
    );
    let appends = commands
        .iter()
        .filter(|c| c.to_uppercase().starts_with("A") && c.to_uppercase().contains("APPEND"))
        .count();
    assert_eq!(
        appends, 1,
        "nessun retry alla cieca: esattamente UN tentativo di APPEND: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve esistere ancora");
    assert!(!st.is_deleted(1), "il vecchio draft uid=1 non deve essere marcato \\Deleted");
    assert!(
        expunge_commands(&commands).is_empty(),
        "nessun EXPUNGE dopo un esito incerto: {commands:?}"
    );
}

/// 4. Successo con UIDPLUS: UID EXPUNGE MIRATO sul solo uid vecchio. Una
///    seconda bozza GIA' marcata \Deleted (uid=2) DEVE restare intatta: e'
///    la prova che si e' passati da expunge() globale a UID EXPUNGE.
#[tokio::test]
async fn uidplus_success_uid_expunge_targets_only_old_uid() {
    let (commands, responses, state) =
        run_scenario(
            FakeConfig { uidplus: true, append: AppendBehavior::Ok { new_uid: 3, appenduid: true, untagged_first: false }, caps_fail: false, uid_expunge_loses_ack: false, silent_second_connection: false },
            &[],
            &[("update_draft", VALID_CALL)],
        )
        .await;

    let text = tool_text(&responses[0]);
    assert!(
        !is_error_response(&responses[0]),
        "lo scenario UIDPLUS valido deve riuscire: {:?}", responses[0]
    );
    // Il nuovo UID arriva dall'APPENDUID.
    assert!(
        text.contains("3"),
        "la risposta deve riportare il nuovo uid=3 da APPENDUID: {text}"
    );
    // UID EXPUNGE mirato presente, con SOLO l'uid vecchio.
    let uid_expunge: Vec<&String> = commands
        .iter()
        .filter(|c| c.to_uppercase().contains("UID EXPUNGE"))
        .collect();
    assert_eq!(
        uid_expunge.len(),
        1,
        "esattamente un UID EXPUNGE: {commands:?}"
    );
    assert!(
        uid_expunge[0].contains("UID EXPUNGE 1"),
        "UID EXPUNGE mirato sul solo uid vecchio 1: {:?}",
        uid_expunge[0]
    );
    // MAI expunge globale.
    let bare = expunge_commands(&commands);
    assert!(
        bare.is_empty(),
        "nessun EXPUNGE globale consentito: {bare:?}"
    );
    // STATO: il vecchio e' rimosso, la seconda bozza \Deleted resta.
    let st = state.lock().unwrap();
    assert!(!st.exists(1), "il vecchio draft uid=1 deve essere stato rimosso");
    assert!(st.exists(2), "la seconda bozza gia' marcata \\Deleted (uid=2) DEVE restare intatta");
    assert!(st.exists(3), "la nuova bozza uid=3 deve essere presente");
}

/// 5. Server SENZA UIDPLUS: nessun expunge globale, vecchio conservato,
///    risposta che dichiara la sostituzione parziale.
#[tokio::test]
async fn no_uidplus_partial_substitution_never_global_expunge() {
    let (commands, responses, state) =
        run_scenario(
            FakeConfig { uidplus: false, append: AppendBehavior::Ok { new_uid: 3, appenduid: false, untagged_first: false }, caps_fail: false, uid_expunge_loses_ack: false, silent_second_connection: false },
            &[],
            &[("update_draft", VALID_CALL)],
        )
        .await;

    let text = tool_text(&responses[0]);
    assert!(
        !is_error_response(&responses[0]),
        "senza UIDPLUS l'operazione si completa con sostituzione parziale: {:?}", responses[0]
    );
    assert!(
        text.to_uppercase().contains("PARTIAL SUBSTITUTION"),
        "la risposta deve dichiarare la sostituzione parziale: {text}"
    );
    assert!(
        !commands.iter().any(|c| c.to_uppercase().contains("UID EXPUNGE")),
        "senza UIDPLUS nessun UID EXPUNGE: {commands:?}"
    );
    assert!(
        expunge_commands(&commands).is_empty(),
        "MAI expunge globale, senza eccezioni: {:?}",
        expunge_commands(&commands)
    );
    assert!(
        !commands.iter().any(|c| c.to_uppercase().contains("STORE")),
        "senza UIDPLUS il vecchio non va nemmeno marcato \\Deleted (un expunge altrui lo cancellerebbe): {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve essere conservato");
    assert!(st.exists(2), "la seconda bozza \\Deleted (uid=2) deve restare intatta");
    assert!(st.exists(3), "la nuova bozza uid=3 deve essere presente");
}

/// A legitimate untagged response BEFORE the continuation (RFC 3501 §2.2.1)
/// must NOT produce a false rejection of the APPEND.
#[tokio::test]
async fn append_untagged_before_continuation_still_succeeds() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: true,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", VALID_CALL)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "l'untagged prima della continuation NON e' un rifiuto: {:?}",
        responses[0]
    );
    let text = tool_text(&responses[0]);
    assert!(
        text.contains("new uid=3"),
        "l'append deve riuscire e riportare il nuovo uid=3: {text}"
    );
    let st = state.lock().unwrap();
    assert!(!st.exists(1), "il vecchio draft deve essere rimosso");
    assert!(st.exists(2), "la seconda bozza \\Deleted resta intatta");
    assert!(st.exists(3), "la nuova bozza deve esistere");
}

/// A CONNECTED but silent peer after the literal => an UNCERTAIN outcome
/// within the operational timeout, not an infinite wait; no retry.
#[tokio::test]
async fn append_silent_after_literal_reports_uncertain() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::SilentAfterLiteral,
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", VALID_CALL)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "il peer silente dopo il literal deve dare errore: {:?}",
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
        combined.contains("UNCERTAIN"),
        "l'esito deve essere dichiarato INCERTO: {combined}"
    );
    let appends = commands
        .iter()
        .filter(|c| c.to_uppercase().contains("APPEND"))
        .count();
    assert_eq!(appends, 1, "nessun retry: {commands:?}");
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
    assert!(
        !st.is_deleted(1),
        "il vecchio draft non deve essere marcato dopo un esito incerto"
    );
}

/// A CAPABILITY failure AFTER a successful append => a conservative error
/// saying "new draft saved, old one untouched".
#[tokio::test]
async fn capability_failure_after_append_reports_conservative() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: true,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", VALID_CALL)],
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
        combined.contains("APPENDED"),
        "l'errore deve dire che il nuovo draft e' stato salvato: {combined}"
    );
    assert!(
        combined.contains("NOT MARKED OR REMOVED") || combined.contains("BOTH DRAFTS PRESENT"),
        "l'errore deve dire che il vecchio non e' stato toccato: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft uid=1 deve essere ancora li'");
    assert!(st.exists(3), "la nuova bozza uid=3 deve essere salvata");
}

/// A lost UID EXPUNGE ACK AFTER it was applied => an error that does NOT
/// claim the old draft still exists: the removal is UNCERTAIN.
#[tokio::test]
async fn uid_expunge_ack_lost_reports_uncertain() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: true,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", VALID_CALL)],
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
        !combined.contains("STILL PRESENT"),
        "l'errore NON deve affermare che il vecchio esiste ancora: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(
        !st.exists(1),
        "sul server l'UID EXPUNGE E' stato applicato: uid=1 rimosso"
    );
    assert!(st.exists(2), "la seconda bozza \\Deleted resta intatta");
    assert!(st.exists(3), "la nuova bozza resta salvata");
}

/// A body over the MIME ceiling => an EARLY rejection, before composing or
/// serializing the message and before any IMAP operation.
#[tokio::test]
async fn update_draft_body_over_preliminary_limit_rejected_before_composing() {
    let big_body = "x".repeat(200);
    let call = format!(
        r#"{{"uid":1,"to":"dest@example.com","subject":"s","body":"{big_body}"}}"#
    );
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[("EMAIL_ATTACH_MAX_MIME_BYTES", "128")],
        &[("update_draft", &call)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "un corpo sopra il tetto deve dare errore: {:?}",
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
        combined.contains("BEFORE COMPOSING") && combined.contains("ALREADY EXCEEDS"),
        "il rifiuto deve essere la guardia ANTICIPATA: {combined}"
    );
    let destructive = commands
        .iter()
        .filter(|c| {
            let u = c.to_uppercase();
            u.contains("APPEND") || u.contains("STORE") || u.contains("EXPUNGE")
        })
        .count();
    assert_eq!(
        destructive, 0,
        "nessun comando IMAP dopo la guardia anticipata: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
}

/// The same early guard applies to `create_draft`.
#[tokio::test]
async fn create_draft_body_over_preliminary_limit_rejected_before_composing() {
    let big_body = "y".repeat(200);
    let call = format!(
        r#"{{"to":"dest@example.com","subject":"s","body":"{big_body}"}}"#
    );
    let (commands, responses, _state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[("EMAIL_ATTACH_MAX_MIME_BYTES", "128")],
        &[("create_draft", &call)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "un corpo sopra il tetto deve dare errore: {:?}",
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
        combined.contains("BEFORE COMPOSING"),
        "il rifiuto deve essere la guardia anticipata: {combined}"
    );
    assert!(
        !commands.iter().any(|c| c.to_uppercase().contains("APPEND")),
        "nessun APPEND dopo la guardia anticipata: {commands:?}"
    );
}

/// `attachments: []` behaves like omitted EVEN without EMAIL_ATTACH_DIR:
/// the operation succeeds.
#[tokio::test]
async fn update_draft_empty_attachments_vector_matches_omitted() {
    let call = r#"{"uid":1,"to":"dest@example.com","subject":"aggiornata","body":"corpo","attachments":[]}"#;
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", call)],
    )
    .await;

    assert!(
        !is_error_response(&responses[0]),
        "[] senza radice NON deve fallire (contratto: [] == omesso): {:?}",
        responses[0]
    );
    let st = state.lock().unwrap();
    assert!(!st.exists(1), "il vecchio draft deve essere sostituito");
    assert!(st.exists(2), "la seconda bozza \\Deleted resta intatta");
    assert!(st.exists(3), "la nuova bozza deve esistere");
}

/// An EFFECTIVE attachment without a root stays rejected, and the rejection
/// (in compose, before the network) leaves the old draft intact.
#[tokio::test]
async fn update_draft_attachment_without_root_rejected_nondestructively() {
    let call = r#"{"uid":1,"to":"dest@example.com","subject":"aggiornata","body":"corpo","attachments":[{"path":"documento.pdf"}]}"#;
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", call)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "un allegato effettivo senza EMAIL_ATTACH_DIR deve dare errore: {:?}",
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
        combined.contains("EMAIL_ATTACH_DIR"),
        "l'errore deve citare la variabile mancante: {combined}"
    );
    let destructive = commands
        .iter()
        .filter(|c| {
            let u = c.to_uppercase();
            u.contains("APPEND") || u.contains("STORE") || u.contains("EXPUNGE")
        })
        .count();
    assert_eq!(
        destructive, 0,
        "nessuna operazione IMAP dopo il rifiuto in compose: {commands:?}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
    assert!(!st.is_deleted(1), "il vecchio draft non deve essere marcato");
}

/// A blocked literal write (a peer that does not read) must produce the
/// uncertain outcome within the OVERALL DEADLINE, not suspend without a
/// limit. A very large literal: the TCP buffers are sure to fill up.
#[tokio::test]
async fn append_write_blocked_by_peer_yields_uncertain_within_deadline() {
    let big_body = "x".repeat(64 * 1024 * 1024);
    let call = format!(
        r#"{{"uid":1,"to":"dest@example.com","subject":"s","body":"{big_body}"}}"#
    );
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::WriteBlocking,
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[("EMAIL_ATTACH_MAX_MIME_BYTES", "134217728")],
        &[("update_draft", &call)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "la write bloccata deve dare errore entro la deadline: {:?}",
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
        combined.contains("UNCERTAIN"),
        "la write bloccata e' un esito INCERTO (literal parzialmente trasferito): {combined}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
    assert!(
        !commands.iter().any(|c| c.to_uppercase().contains("STORE")),
        "nessuno store dopo un esito incerto: {commands:?}"
    );
}

/// A server sending untagged traffic forever before the continuation must
/// NOT keep the operation open indefinitely: the overall deadline fires
/// even if a per-read timer would be rearmed.
#[tokio::test]
async fn append_infinite_untagged_hits_overall_deadline() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::InfiniteUntagged,
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[],
        &[("update_draft", VALID_CALL)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "untagged infinito deve dare errore entro la deadline: {:?}",
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
        combined.contains("DEADLINE EXPIRED"),
        "l'errore deve citare la deadline complessiva: {combined}"
    );
    assert!(
        combined.contains("NOT TRANSFERRED"),
        "prima del literal il messaggio NON e' stato trasferito: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
}

/// A DEDICATED connection whose handshake/login hangs (peer accepts and
/// goes silent) => an error within the operational timeout, with a truthful
/// message: nothing transferred, old draft intact, connection discarded.
#[tokio::test]
async fn dedicated_connect_silent_login_reports_nothing_transferred() {
    let (commands, responses, state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: true,
        },
        &[],
        &[("update_draft", VALID_CALL)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "la connect dedicata bloccata deve dare errore: {:?}",
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
        combined.contains("NOTHING WAS TRANSFERRED"),
        "l'errore deve dire che nulla e' stato trasferito: {combined}"
    );
    assert!(
        combined.contains("OLD DRAFT IS INTACT"),
        "l'errore deve dire che il vecchio draft e' intatto: {combined}"
    );
    let st = state.lock().unwrap();
    assert!(st.exists(1), "il vecchio draft resta intatto");
    assert!(
        !commands.iter().any(|c| {
            let u = c.to_uppercase();
            u.contains("STORE") || u.contains("EXPUNGE")
        }),
        "nessun comando distruttivo senza append: {commands:?}"
    );
}

/// The preflight wins OVER address validation too: body over the ceiling +
/// an invalid `to` => a SIZE error (the guard runs before the builder and
/// the parses; no point allocating at all).
#[tokio::test]
async fn preflight_wins_over_address_validation() {
    let big_body = "x".repeat(200);
    let call = format!(
        r#"{{"uid":1,"to":"non-e-una-email","subject":"s","body":"{big_body}"}}"#
    );
    let (commands, responses, _state) = run_scenario(
        FakeConfig {
            uidplus: true,
            append: AppendBehavior::Ok {
                new_uid: 3,
                appenduid: true,
                untagged_first: false,
            },
            caps_fail: false,
            uid_expunge_loses_ack: false,
            silent_second_connection: false,
        },
        &[("EMAIL_ATTACH_MAX_MIME_BYTES", "128")],
        &[("update_draft", &call)],
    )
    .await;

    assert!(
        is_error_response(&responses[0]),
        "deve dare errore: {:?}",
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
        combined.contains("BEFORE COMPOSING") && combined.contains("ALREADY EXCEEDS"),
        "l'errore deve essere quello della guardia anticipata, non quello degli indirizzi: {combined}"
    );
    assert!(
        !combined.contains("INVALID TO"),
        "il parse degli indirizzi NON deve precedere il preflight: {combined}"
    );
}
