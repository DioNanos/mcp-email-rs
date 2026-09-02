//! `list_emails_with_headers` must return the headers it asked for.
//!
//! The tool requests `BODY[HEADER.FIELDS (...)]` but read the result
//! with `fetch.body()`, which matches only `BodySection { section: None }`
//! and `Rfc822` — an `HEADER.FIELDS` section comes back as
//! `Some(SectionPath::Full(MessageSection::Header))` (imap-proto parser,
//! body.rs: `HEADER.FIELDS (...)` maps to `MessageSection::Header`), so
//! `body()` returned `None` on every message and the tool shipped empty
//! headers. The accessor that matches what the tool ASKS for is
//! `fetch.header()` (async-imap `types/fetch.rs:90`).
//!
//! Scope note: the \Seen side effect of non-PEEK fetches is D-112 and
//! lives on its own branch; this fake does not model it.

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

const HEADER_LINES: &str = "From: sender@example.com\r\nSubject: Peek test\r\nDate: Mon, 31 Aug 2026 10:00:00 +0200\r\n\r\n";

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

/// Scripted IMAP server: answers `UID SEARCH ALL` with message 1 and
/// serves the requested fetch items (ENVELOPE summary and the
/// `HEADER.FIELDS` literal), so the tool can be exercised end to end.
async fn fake_imap_loop(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
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
                let mut parts = line.splitn(3, ' ');
                let tag = parts.next().unwrap_or("").to_string();
                let cmd = parts.next().unwrap_or("").to_string();
                let rest = parts.next().unwrap_or("");
                let upper = format!("{} {}", cmd, rest).to_uppercase();
                let mut response = if upper.contains("SEARCH") {
                    "* SEARCH 1".to_string()
                } else if upper.contains("FETCH") && upper.contains("HEADER.FIELDS") {
                    format!(
                        "* 1 FETCH (UID 1 FLAGS () ENVELOPE (\"Mon, 31 Aug 2026 10:00:00 +0200\" \"Peek test\" ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"reader\" \"example.com\")) NIL NIL NIL \"<peek@example.com>\") RFC822.SIZE 215 BODY[HEADER.FIELDS (FROM SUBJECT DATE)] {{{}}}\r\n",
                        HEADER_LINES.len()
                    ) + HEADER_LINES
                        + ")"
                } else if upper.contains("FETCH") {
                    "* 1 FETCH (UID 1 FLAGS () ENVELOPE (\"Mon, 31 Aug 2026 10:00:00 +0200\" \"Peek test\" ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"sender\" \"example.com\")) ((NIL NIL \"reader\" \"example.com\")) NIL NIL NIL \"<peek@example.com>\") RFC822.SIZE 215)".to_string()
                } else {
                    String::new()
                };
                if !response.is_empty() {
                    response.push_str(&format!("\r\n{}\r\n", ok(&tag)));
                    let _ = wr.write_all(response.as_bytes()).await;
                } else {
                    let _ = wr.write_all(format!("{}\r\n", ok(&tag)).as_bytes()).await;
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
        client.send(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"headers-read-test","version":"0"}}}"#);
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

fn tool_text(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Con gli header presenti sul server, il tool deve restituirli NON
/// vuoti: il difetto sopravvive a qualunque test che verifichi solo
/// che la chiamata riesca, quindi qui si asserisce il contenuto.
#[tokio::test]
async fn requested_headers_arrive_not_empty() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(fake_imap_loop(listener, tls_acceptor()));

    let config_path = std::env::temp_dir().join(format!("headers-read-test-{}.toml", port));
    std::fs::write(
        &config_path,
        format!(
            "[imap]\nhost = \"127.0.0.1\"\nport = {port}\nuser = \"test@local\"\npassword = \"test\"\ntls = true\ntls_reject_unauthorized = false\nauth = \"plain\"\n\n[pool]\nmax_connections = 1\nidle_timeout_secs = 60\noperation_timeout_secs = 10\n"
        ),
    )
    .expect("config di test scrivibile");
    let config_str = config_path.to_str().unwrap().to_string();

    let responses: Shared<Vec<serde_json::Value>> = Arc::new(Mutex::new(Vec::new()));
    let responses_for_driver = responses.clone();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let driver = std::thread::spawn(move || {
        let mut client = McpClient::spawn(&config_str);
        let resp = client.call(
            1,
            "list_emails_with_headers",
            r#"{"headers":["From","Subject","Date"],"limit":5}"#,
        );
        responses_for_driver
            .lock()
            .unwrap()
            .push(resp.unwrap_or_default());
        let _ = done_tx.blocking_send(());
    });
    let drove = tokio::time::timeout(Duration::from_secs(90), done_rx.recv()).await;
    assert!(drove.is_ok(), "driver MCP non completato entro il timeout");
    let _ = driver.join();
    let _ = std::fs::remove_file(&config_path);

    let responses = responses.lock().unwrap().clone();
    assert_eq!(responses.len(), 1);
    let response = &responses[0];
    let text = tool_text(response);
    assert!(!text.is_empty(), "risposta vuota dal tool: {response:?}");
    assert!(
        text.contains("From: sender@example.com"),
        "gli header richiesti non sono arrivati (restano vuoti): {text} | RAW: {response:?}"
    );
    assert!(
        text.contains("Subject: Peek test"),
        "manca l'header Subject richiesto: {text}"
    );
}
