//! Reading a message must NOT mark it as seen.
//!
//! IMAP: any content fetch without `.PEEK` (RFC822, RFC822.HEADER,
//! BODY[...]) sets `\Seen` on the message. A reading tool must not
//! mutate the state of the user's mailbox: mark-as-read is an explicit
//! action (`mark_seen`), not a side effect of looking.
//!
//! These tests assert on STATE, not on emitted bytes: the fake IMAP
//! server models the semantics of the wire — a non-PEEK content fetch
//! flips the message to `\Seen` — and the follow-up summary fetch
//! reports the flags the server now holds. Reading through the tools
//! must leave the flag untouched; `mark_seen` must still set it.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader as AsyncBufReader};
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

const RAW_MESSAGE: &str = "From: sender@example.com\r\n\
To: reader@example.com\r\n\
Subject: Peek test\r\n\
Date: Mon, 31 Aug 2026 10:00:00 +0200\r\n\
Message-ID: <peek@example.com>\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
\r\n\
Corpo del messaggio di prova.\r\n";

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

fn ok(tag: &str) -> String {
    format!("{} OK", tag)
}

/// Scripted IMAP server that MODELS the side effect under test: a
/// content fetch without `.PEEK` flips the stored message to `\Seen`
/// (RFC 3501: a non-PEEK body section fetch implies `\Seen`). The
/// flags reported in any later fetch reflect that stored state, which
/// is exactly what the tests assert on.
async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    log: Shared<Vec<String>>,
    seen: Shared<bool>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
        let log = log.clone();
        let seen = seen.clone();
        tokio::spawn(async move {
            let mut stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = stream
                .write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fake server\r\n")
                .await;
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut lines = AsyncBufReader::new(&mut rd).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log.lock().unwrap().push(line.clone());
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("").to_string();
                let cmd = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let upper = format!("{} {}", cmd, rest).to_uppercase();
                let is_store_seen = upper.contains("STORE") && upper.contains("\\SEEN");
                if is_store_seen {
                    *seen.lock().unwrap() = true;
                    for r in ["* 1 FETCH (FLAGS (\\Seen))".to_string(), ok(&tag)] {
                        let _ = wr.write_all(format!("{}\r\n", r).as_bytes()).await;
                    }
                    continue;
                }
                if upper.contains("FETCH") {
                    let peek_header = upper.contains("BODY.PEEK[HEADER");
                    let peek_body = upper.contains("BODY.PEEK[]");
                    let nonpeek_body = upper.contains("BODY[");
                    let rfc822_content = upper.contains("RFC822") && !upper.contains("RFC822.SIZE");
                    let is_peek = peek_header || peek_body;
                    let content_fetch = peek_header || peek_body || nonpeek_body || rfc822_content;
                    if content_fetch && !is_peek {
                        // The wire semantics under test: a non-PEEK
                        // content fetch implies \Seen.
                        *seen.lock().unwrap() = true;
                    }
                    let flags = if *seen.lock().unwrap() { "\\Seen" } else { "" };
                    let flags_part = if flags.is_empty() {
                        "".to_string()
                    } else {
                        format!("FLAGS ({flags}) ")
                    };
                    let mut response = if peek_header {
                        let headers = "From: sender@example.com\r\nSubject: Peek test\r\n";
                        format!(
                            "* 1 FETCH (UID 1 {flags_part}BODY[HEADER.FIELDS (FROM SUBJECT)] {{{}}}\r\n",
                            headers.len()
                        ) + headers
                            + ")"
                    } else if content_fetch {
                        // Il server risponde con l'ITEM RICHIESTO: a
                        // RFC822 risponde RFC822, a BODY.PEEK[...] risponde
                        // BODY[...] (senza PEEK, come i server reali).
                        let (item, payload) = if rfc822_content {
                            ("RFC822", RAW_MESSAGE)
                        } else {
                            ("BODY[]", RAW_MESSAGE)
                        };
                        format!(
                            "* 1 FETCH (UID 1 {flags_part}{item} {{{}}}\r\n",
                            payload.len()
                        ) + payload
                            + ")"
                    } else {
                        format!(
                            "* 1 FETCH (UID 1 FLAGS ({flags}) ENVELOPE (\"Mon, 31 Aug 2026 10:00:00 +0200\" \"Peek test\" ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"reader\" \"example.com\")) NIL NIL NIL \"<peek@example.com>\") RFC822.SIZE {})",
                            RAW_MESSAGE.len()
                        )
                    };
                    // Il CRLF finale della riga tagged e' OBBLIGATORIO:
                    // senza, il client resta in incomplete per sempre.
                    response.push_str(&format!("\r\n{}\r\n", ok(&tag)));
                    let _ = wr.write_all(response.as_bytes()).await;
                    continue;
                }
                let resp: Vec<String> = if upper.contains("SEARCH") {
                    vec!["* SEARCH 1".into(), ok(&tag)]
                } else if upper.starts_with("CAPABILITY") {
                    vec!["* CAPABILITY IMAP4rev1 AUTH=PLAIN".into(), ok(&tag)]
                } else if upper.starts_with("LOGIN") || upper.starts_with("NOOP") {
                    vec![ok(&tag)]
                } else if upper.starts_with("LIST") {
                    vec!["* LIST (\\HasNoChildren) \"/\" \"INBOX\"".into(), ok(&tag)]
                } else if upper.starts_with("SELECT") {
                    // La SELECT NON tocca lo stato: i flag del messaggio
                    // persistono nella mailbox per tutta la sessione.
                    vec![
                        "* 1 EXISTS".into(),
                        "* 0 RECENT".into(),
                        "* FLAGS (\\Seen)".into(),
                        "* OK [UIDVALIDITY 1]".into(),
                        "* OK [UIDNEXT 2]".into(),
                        format!("{} OK [READ-WRITE] SELECT", tag),
                    ]
                } else if upper.starts_with("LOGOUT") {
                    vec!["* BYE".into(), format!("{} OK LOGOUT", tag)]
                } else {
                    vec![format!("{} OK ignored", tag)]
                };
                for r in resp {
                    let _ = wr.write_all(format!("{}\r\n", r).as_bytes()).await;
                }
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
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"peek-read-test","version":"0"}}}"#);
        let _ = client.wait_for_id(0);
        client.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        client
    }

    fn send(&mut self, line: &str) {
        let stdin = self.child.stdin.as_mut().expect("stdin del binario");
        stdin
            .write_all(format!("{}\n", line).as_bytes())
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
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"{}","arguments":{}}}}}"#,
            id, name, arguments
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

/// Text of the first content block of a tool response, for assertions.
fn tool_text(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Pin the wire property for a single content-reading tool. Metadata fetches
/// such as ENVELOPE/RFC822.SIZE are deliberately ignored here.
fn assert_content_fetches_are_peek(commands: &[String], tool: &str) {
    let content_fetches = commands
        .iter()
        .filter(|command| {
            let upper = command.to_uppercase();
            upper.contains("FETCH")
                && (upper.contains("BODY[")
                    || upper.contains("BODY.PEEK")
                    || (upper.contains("RFC822") && !upper.contains("RFC822.SIZE")))
        })
        .collect::<Vec<_>>();
    assert!(
        !content_fetches.is_empty(),
        "{tool}: nessun fetch di contenuto osservato sul wire: {commands:?}"
    );
    let non_peek = content_fetches
        .into_iter()
        .filter(|command| !command.to_uppercase().contains("BODY.PEEK"))
        .cloned()
        .collect::<Vec<_>>();
    assert!(
        non_peek.is_empty(),
        "{tool}: fetch di contenuto senza BODY.PEEK sul wire:\n{}",
        non_peek.join("\n")
    );
}

/// Esegue le chiamate MCP contro il fake IMAP e restituisce i comandi
/// intercettati sul wire e le risposte JSON-RPC, in ordine di chiamata.
async fn run_scenario(calls: &[(&str, &str)]) -> (Vec<String>, Vec<serde_json::Value>) {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    let seen: Shared<bool> = Arc::new(Mutex::new(false));
    tokio::spawn(fake_imap_loop(
        listener,
        tls_acceptor(),
        commands.clone(),
        seen.clone(),
    ));

    let config_path = std::env::temp_dir().join(format!("peek-read-test-{}.toml", port));
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
    (commands, responses)
}

/// Il cuore del difetto: leggere non deve marcare come letta.
/// Due asserzioni nella stessa prova: il contenuto ARRIVA (un fix
/// ingenuo di PEEK può rompere il parsing e restituire corpo vuoto in
/// silenzio) e il flag `\Seen` non viene impostato.
#[tokio::test]
async fn reading_a_message_does_not_mark_it_seen_and_content_arrives() {
    let (commands, responses) = run_scenario(&[
        ("get_email", r#"{"uid":1}"#),
        (
            "list_emails_with_headers",
            r#"{"headers":["from","subject"],"limit":5}"#,
        ),
        ("list_emails", r#"{"limit":5}"#),
    ])
    .await;
    assert_eq!(responses.len(), 3);

    // Il contenuto arriva davvero (nessun corpo vuoto in silenzio).
    let read_text = tool_text(&responses[0]);
    assert!(
        read_text.contains("Corpo del messaggio di prova."),
        "il corpo del messaggio non e' arrivato dopo la lettura: {read_text} | RAW: {:?}",
        responses[0]
    );

    // STATO: dopo le tre letture, il server non ha il messaggio in \Seen.
    let list_text = tool_text(&responses[2]);
    assert!(
        !list_text.contains("Seen"),
        "la lettura ha marcato il messaggio come letto (stato server): {list_text}"
    );

    // Proprieta' sul wire: nessun comando di fetch contenuto inviato
    // senza .PEEK (il fake gia' modella l'effetto; qui resta la traccia).
    let non_peek = commands
        .iter()
        .filter(|c| c.contains("FETCH"))
        .filter(|c| {
            let u = c.to_uppercase();
            (u.contains("BODY[") || (u.contains("RFC822") && !u.contains("RFC822.SIZE")))
                && !u.contains("BODY.PEEK")
        })
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        non_peek.is_empty(),
        "fetch di contenuto senza .PEEK sul wire:\n{non_peek}"
    );
}

#[tokio::test]
async fn get_email_raw_pins_peek_on_the_wire() {
    let (commands, responses) = run_scenario(&[("get_email_raw", r#"{"uid":1}"#)]).await;
    assert_eq!(responses.len(), 1);
    assert_content_fetches_are_peek(&commands, "get_email_raw");
}

#[tokio::test]
async fn get_bodystructure_pins_peek_on_the_wire() {
    let (commands, responses) = run_scenario(&[("get_bodystructure", r#"{"uid":1}"#)]).await;
    assert_eq!(responses.len(), 1);
    assert_content_fetches_are_peek(&commands, "get_bodystructure");
}

#[tokio::test]
async fn download_attachment_pins_peek_on_the_wire() {
    let (commands, responses) =
        run_scenario(&[("download_attachment", r#"{"uid":1,"part_id":"1"}"#)]).await;
    assert_eq!(responses.len(), 1);
    assert_content_fetches_are_peek(&commands, "download_attachment");
}

/// Controllo negativo del controllo: la capacita' di marcare come letto
/// resta. `mark_seen` deve continuare a impostare `\Seen` sul server.
#[tokio::test]
async fn mark_seen_still_marks_the_message_seen() {
    let (_, responses) = run_scenario(&[
        ("mark_seen", r#"{"uid":1,"seen":true}"#),
        ("list_emails", r#"{"limit":5}"#),
    ])
    .await;
    let list_text = tool_text(&responses[1]);
    assert!(
        list_text.contains("Seen"),
        "mark_seen non ha piu' effetto sullo stato del server: {list_text}"
    );
}
