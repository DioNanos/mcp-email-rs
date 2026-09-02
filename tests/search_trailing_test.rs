// Regression tests: what reaches the IMAP wire.
//
// Both tests assert on the EMITTED command bytes, not on result counts:
// a count would stay green exactly when the failures happen.
//
// 1) trailing space: rigorous IMAP servers (Gmail) answer `BAD Could not
//    parse command` to a command ending in `<SPACE><CRLF>`, and async-imap
//    0.11.2 swallows the tagged BAD returning an empty set — the tool then
//    reports "[]" as if the mailbox were legitimately empty.
// 2) Gmail X-GM-RAW quoting: the Gmail search language treats a QUOTED
//    value as an exact-phrase match, so `from:"alpine"` does NOT match
//    a message from alpine-lodge@example.com, while the bare
//    token `from:alpine` does. Simple tokens must be emitted unquoted;
//    multi-word values keep the quoted phrase form.
//
// The tests spawn the real binary (MCP over stdio) against an in-process
// fake IMAP server (implicit TLS, self-signed fixture certificate, config
// forces tls_reject_unauthorized=false) and inspect every command line the
// server receives.
//
// The fixture certificate MAY be expired: it is not an accident to fix.
// tls_reject_unauthorized=false routes the client through the NoVerifier
// in src/pool.rs, which accepts every certificate by design, so expiry is
// irrelevant here and the fixture never needs regenerating for these tests.

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

/// Minimal scripted IMAP server: logs every command line it receives and
/// answers with canned responses (one message, UID 1). Answering "results"
/// regardless of the criteria keeps the client flow going: what these tests
/// measure is the shape of the request, not the interpretation.
async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    log: Shared<Vec<String>>,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
        let log = log.clone();
        tokio::spawn(async move {
            eprintln!("[fake-imap] connessione in arrivo");
            let mut stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[fake-imap] handshake TLS fallito: {e}");
                    return;
                }
            };
            eprintln!("[fake-imap] handshake TLS ok");
            let _ = stream
                .write_all(b"* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] fake server\r\n")
                .await;
            let (mut rd, mut wr) = tokio::io::split(stream);
            let mut lines = AsyncBufReader::new(&mut rd).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                eprintln!("[fake-imap] C: {line}");
                log.lock().unwrap().push(line.clone());
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("").to_string();
                let cmd = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let upper = format!("{} {}", cmd, rest).to_uppercase();
                let resp: Vec<String> = if upper.starts_with("CAPABILITY") {
                    vec!["* CAPABILITY IMAP4rev1 AUTH=PLAIN".into(), ok(&tag)]
                } else if upper.starts_with("LOGIN") || upper.starts_with("NOOP") {
                    vec![ok(&tag)]
                } else if upper.starts_with("LIST") {
                    vec!["* LIST (\\HasNoChildren) \"/\" \"INBOX\"".into(), ok(&tag)]
                } else if upper.starts_with("SELECT") {
                    vec![
                        "* 1 EXISTS".into(),
                        "* 0 RECENT".into(),
                        "* FLAGS (\\Seen)".into(),
                        "* OK [UIDVALIDITY 1]".into(),
                        "* OK [UIDNEXT 2]".into(),
                        format!("{} OK [READ-WRITE] SELECT", tag),
                    ]
                } else if upper.contains("SEARCH") {
                    vec!["* SEARCH 1".into(), format!("{} OK SEARCH", tag)]
                } else if upper.contains("FETCH") {
                    vec![
                        "* 1 FETCH (UID 1 FLAGS () RFC822.SIZE 100 ENVELOPE (\"Mon, 25 Aug 2026 10:00:00 +0200\" \"T\" ((\"T\" NIL \"t\" \"t.example\")) ((\"T\" NIL \"t\" \"t.example\")) ((\"T\" NIL \"t\" \"t.example\")) ((NIL NIL \"d\" \"d.example\")) NIL NIL NIL \"<1@t.example>\"))".into(),
                        format!("{} OK FETCH", tag),
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
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tls-boundary-test","version":"0"}}}"#);
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
                eprintln!("[driver] EOF dal binario (attesa id {id})");
                return None;
            }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line)
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

/// Esegue le chiamate MCP indicate contro il fake IMAP e restituisce i
/// comandi intercettati e le risposte JSON-RPC, in ordine di chiamata.
/// `gmail_host` attiva il percorso X-GM-RAW del server: l'host contiene
/// "gmail" e nip.io lo risolve a 127.0.0.1 (serve risoluzione DNS attiva).
async fn run_scenario(
    calls: &[(&str, &str)],
    gmail_host: bool,
) -> (Vec<String>, Vec<serde_json::Value>) {
    // il crate usa rustls con feature "ring": il provider va installato
    // esplicitamente nel processo di test (nel binario avviene altrove)
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(fake_imap_loop(listener, tls_acceptor(), commands.clone()));

    let host = if gmail_host {
        "gmail.127.0.0.1.nip.io"
    } else {
        "127.0.0.1"
    };
    let config_path = std::env::temp_dir().join(format!("tls-boundary-test-{}.toml", port));
    std::fs::write(
        &config_path,
        format!(
            "[imap]\nhost = \"{host}\"\nport = {port}\nuser = \"test@local\"\npassword = \"test\"\ntls = true\ntls_reject_unauthorized = false\nauth = \"plain\"\n\n[pool]\nmax_connections = 1\nidle_timeout_secs = 60\noperation_timeout_secs = 10\n"
        ),
    )
    .expect("config di test scrivibile");

    // il driver MCP è sincrono (stdin/stdout bloccanti): gira su un thread
    // dedicato; l'attesa passa da un canale tokio così il runtime resta
    // libero di servire il fake IMAP
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
    assert!(drove.is_ok(), "driver MCP non completato entro il timeout");
    let _ = driver.join();
    let _ = std::fs::remove_file(&config_path);

    let commands = commands_for_driver.lock().unwrap().clone();
    let responses = responses.lock().unwrap().clone();
    (commands, responses)
}

#[tokio::test]
async fn uid_search_commands_reach_the_wire_without_trailing_space() {
    let (commands, _) = run_scenario(
        &[
            (
                "list_emails",
                r#"{"folder":"INBOX","unseen_only":true,"limit":5}"#,
            ),
            (
                "list_emails",
                r#"{"folder":"INBOX","since_date":"24-Aug-2026","limit":5}"#,
            ),
            ("search_emails", r#"{"from":"alpine","limit":5}"#),
            (
                "search_emails",
                r#"{"body":"alpine","since":"01-Aug-2026","limit":5}"#,
            ),
        ],
        false,
    )
    .await;

    let searches: Vec<String> = commands
        .iter()
        .filter(|c| c.contains("SEARCH"))
        .cloned()
        .collect();
    assert!(
        !searches.is_empty(),
        "nessun comando SEARCH intercettato: il percorso non è stato esercitato.\ncomandi: {:?}",
        commands
    );

    // il percorso è davvero quello dei filtri (non solo ALL di fallback)
    assert!(
        searches.iter().any(|c| c.contains("UNSEEN")),
        "manca la UNSEEN: {:?}",
        searches
    );
    assert!(
        searches.iter().any(|c| c.contains("SINCE")),
        "manca una SINCE: {:?}",
        searches
    );
    assert!(
        searches
            .iter()
            .any(|c| c.contains("FROM") || c.contains("X-GM-RAW")),
        "manca il criterio stringa (FROM/X-GM-RAW): {:?}",
        searches
    );

    // La causa: nessun comando SEARCH può finire con uno spazio
    let trailing: Vec<&String> = searches.iter().filter(|c| c.ends_with(' ')).collect();
    assert!(
        trailing.is_empty(),
        "comandi SEARCH con spazio finale (BAD silenzioso sui server rigorosi):\n  {}",
        trailing
            .iter()
            .map(|s| format!("{:?}", s))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

#[tokio::test]
async fn gmail_x_gm_raw_terms_quote_only_when_needed() {
    let (commands, responses) = run_scenario(
        &[
            // token semplice: DEVE andare senza virgolette (frase esatta non matcha)
            ("search_emails", r#"{"from":"alpine","limit":5}"#),
            // token con indirizzo completo: comunque un token
            ("search_emails", r#"{"to":"utente@example.com","limit":5}"#),
            // valore multi-parola: DEVE restare frase quotata
            ("search_emails", r#"{"from":"John Smith","limit":5}"#),
            // virgolette nel valore: rifiuto esplicito, non query ambigua
            ("search_emails", r#"{"from":"sa\"ntander","limit":5}"#),
            // valore vuoto: rifiuto esplicito
            ("search_emails", r#"{"from":"","limit":5}"#),
        ],
        true,
    )
    .await;

    let gm: Vec<String> = commands
        .iter()
        .filter(|c| c.contains("X-GM-RAW"))
        .cloned()
        .collect();
    assert!(!gm.is_empty(), "nessun comando X-GM-RAW: {:?}", commands);

    // token semplici SENZA virgolette annidate (la causa del sintomo 3)
    assert!(
        gm.iter().any(|c| c.contains(r#"X-GM-RAW "from:alpine""#)),
        "atteso il termine non quotato from:alpine, ricevuti: {:?}",
        gm
    );
    assert!(
        gm.iter()
            .any(|c| c.contains(r#"X-GM-RAW "to:utente@example.com""#)),
        "atteso il termine non quotato to:utente@example.com, ricevuti: {:?}",
        gm
    );
    // NESSUN comando può contenere la frase esatta su un token semplice
    let misquoted: Vec<&String> = gm
        .iter()
        .filter(|c| c.contains(r#"from:\"alpine\""#) || c.contains(r#"to:\"utente@example.com\""#))
        .collect();
    assert!(
        misquoted.is_empty(),
        "token semplici emessi come frase esatta (0 risultati su Gmail):\n  {}",
        misquoted
            .iter()
            .map(|s| format!("{:?}", s))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // multi-parola: la frase resta quotata (con escape IMAP del livello esterno)
    assert!(
        gm.iter()
            .any(|c| c.contains(r#"X-GM-RAW "from:\"John Smith\"""#)),
        "attesa la frase quotata from:\"John Smith\", ricevuti: {:?}",
        gm
    );

    // virgolette nel valore e valore vuoto: il tool deve FALLIRE in modo
    // visibile (isError/error), non emettere una query ambigua né "[]"
    let responses_text = format!("{:?}", responses);
    assert!(
        responses
            .iter()
            .any(|r| r.get("error").is_some() || r["result"]["isError"] == true),
        "atteso almeno un fallimento esplicito per i valori non rappresentabili; risposte: {}",
        responses_text
    );
    let gm_bad_quote = gm
        .iter()
        .filter(|c| c.contains(r#"sa\"ntander"#) || c.contains(r#"from:\"\""#));
    assert!(
        gm_bad_quote.count() == 0,
        "query emessa per un valore non rappresentabile (virgolette/vuoto): {:?}",
        gm
    );
}
