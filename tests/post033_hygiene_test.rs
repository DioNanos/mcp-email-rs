//! Post-0.3.3 hygiene pins.
//!
//! The insecure-TLS mode must never be silent: with
//! `tls_reject_unauthorized = false` every new connection logs a
//! clearly prefixed warning on stderr; the default (verified) path
//! logs none. The default itself must not change.
//!
//! `get_bodystructure` keeps the `BODY.PEEK[]` content fetch
//! for now. This test pins the PEEK fetch against RFC822 regression
//! while the BODYSTRUCTURE migration remains a separate issue.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
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

const WARNING_PREFIX: &str = "WARNING: TLS certificate verification DISABLED";

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

/// Scripted IMAP server: serves the content fetch with the configured
/// raw message so the tools can be exercised end to end.
async fn fake_imap_loop(
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    log: Shared<Vec<String>>,
    raw: String,
) {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => return,
        };
        let acceptor = acceptor.clone();
        let log = log.clone();
        let raw = raw.clone();
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
                let mut response = if upper.contains("SEARCH") {
                    "* SEARCH 1".to_string()
                } else if upper.contains("FETCH") {
                    format!("* 1 FETCH (UID 1 FLAGS () BODY[] {{{}}}\r\n", raw.len())
                        + raw.as_str()
                        + ")"
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

struct McpRun {
    commands: Vec<String>,
    stderr: String,
    responses: Vec<serde_json::Value>,
}

/// Spawns the real binary against the fake IMAP server, runs the tool
/// calls, and collects the wire commands plus the binary's stderr.
async fn run_scenario_with(calls: &[(&str, &str)], insecure_tls: bool, raw: &str) -> McpRun {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake imap");
    let port = listener.local_addr().expect("local addr").port();
    let commands: Shared<Vec<String>> = Arc::new(Mutex::new(Vec::new()));
    let raw_owned = raw.to_string();
    tokio::spawn(fake_imap_loop(
        listener,
        tls_acceptor(),
        commands.clone(),
        raw_owned,
    ));

    let tls_line = if insecure_tls {
        "tls = true\ntls_reject_unauthorized = false\n"
    } else {
        "tls = true\n"
    };
    let config_path = std::env::temp_dir().join(format!("post033-hygiene-{}.toml", port));
    std::fs::write(
        &config_path,
        format!(
            "[imap]\nhost = \"127.0.0.1\"\nport = {port}\nuser = \"test@local\"\npassword = \"test\"\n{tls_line}auth = \"plain\"\n\n[pool]\nmax_connections = 1\nidle_timeout_secs = 60\noperation_timeout_secs = 10\n"
        ),
    )
    .expect("config di test scrivibile");
    let config_str = config_path.to_str().unwrap().to_string();

    let stderr_path = format!("{}.stderr", config_path.to_str().unwrap());
    let calls_owned: Vec<(u64, String, String)> = calls
        .iter()
        .enumerate()
        .map(|(i, (name, args))| (i as u64 + 1, name.to_string(), args.to_string()))
        .collect();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let commands_for_driver = commands.clone();
    let responses: Shared<Vec<serde_json::Value>> = Arc::new(Mutex::new(Vec::new()));
    let responses_for_driver = responses.clone();
    let stderr_path_for_driver = stderr_path.clone();
    let driver = std::thread::spawn(move || {
        let stderr_log =
            std::fs::File::create(&stderr_path_for_driver).expect("stderr capture apribile");
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-email-rs"))
            .env("EMAIL_CONFIG", &config_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_log))
            .spawn()
            .expect("binario avviabile");
        let stdout = child.stdout.take().expect("stdout del binario");
        let mut reader = BufReader::new(stdout);
        let stdin = child.stdin.as_mut().expect("stdin del binario");
        let mut send = |line: &str| {
            stdin
                .write_all(format!("{}\n", line).as_bytes())
                .expect("scrittura su stdin");
            stdin.flush().expect("flush stdin");
        };
        let mut wait_for_id = |id: u64| -> Option<serde_json::Value> {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let mut buf = String::new();
            while std::time::Instant::now() < deadline {
                buf.clear();
                match reader.read_line(&mut buf) {
                    Ok(0) | Err(_) => return None,
                    Ok(_) => {}
                }
                if let Some(v) = serde_json::from_str::<serde_json::Value>(buf.trim())
                    .ok()
                    .filter(|v| v.get("id").and_then(|i| i.as_u64()) == Some(id))
                {
                    return Some(v);
                }
            }
            None
        };
        send(
            r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"post033-hygiene","version":"0"}}}"#,
        );
        let _ = wait_for_id(0);
        send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        for (id, name, args) in calls_owned {
            let req = format!(
                r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"{}","arguments":{}}}}}"#,
                id, name, args
            );
            send(&req);
            let resp = wait_for_id(id).unwrap_or_default();
            responses_for_driver.lock().unwrap().push(resp);
        }
        let _ = child.stdin.take();
        let _ = child.wait();
        let _ = done_tx.blocking_send(());
    });
    let drove = tokio::time::timeout(Duration::from_secs(90), done_rx.recv()).await;
    assert!(drove.is_ok(), "driver MCP non completato entro il timeout");
    let _ = driver.join();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_file(&config_path);
    let _ = std::fs::remove_file(&stderr_path);

    let commands = commands_for_driver.lock().unwrap().clone();
    let responses = responses.lock().unwrap().clone();
    McpRun {
        commands,
        stderr,
        responses,
    }
}

fn tool_text(response: &serde_json::Value) -> String {
    response["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// First verse: the insecure connection must NOT be silent — the prefixed
/// warning appears on stderr.
#[tokio::test]
async fn insecure_tls_connection_logs_a_loud_warning() {
    let run = run_scenario_with(&[("get_bodystructure", r#"{"uid":1}"#)], true, RAW_MESSAGE).await;
    assert!(
        run.stderr.contains(WARNING_PREFIX),
        "connessione insecure senza avviso su stderr. stderr:\n{}",
        run.stderr
    );
}

/// Second verse (negative control): the verified (default) path does not
/// emit the warning — otherwise the warning would lose all meaning.
#[tokio::test]
async fn secure_tls_connection_does_not_log_the_warning() {
    let run = run_scenario_with(&[("get_bodystructure", r#"{"uid":1}"#)], false, RAW_MESSAGE).await;
    assert!(
        !run.stderr.contains(WARNING_PREFIX),
        "il percorso verificato NON deve emettere l'avviso. stderr:\n{}",
        run.stderr
    );
}

/// Current state (declared fallback): get_bodystructure uses BODY.PEEK[] —
/// never non-peek RFC822. The BODYSTRUCTURE migration is a separate issue.
#[tokio::test]
async fn get_bodystructure_fetches_content_with_peek_only() {
    let run = run_scenario_with(&[("get_bodystructure", r#"{"uid":1}"#)], true, RAW_MESSAGE).await;
    let fetch_cmds: Vec<&String> = run
        .commands
        .iter()
        .filter(|c| c.to_uppercase().contains("FETCH"))
        .collect();
    assert!(!fetch_cmds.is_empty(), "nessun FETCH inviato");
    for c in &fetch_cmds {
        let u = c.to_uppercase();
        assert!(
            u.contains("BODY.PEEK[]"),
            "la FETCH di get_bodystructure non usa BODY.PEEK[]: {c}"
        );
        assert!(
            !u.contains("RFC822") && !u.contains("BODYSTRUCTURE"),
            "la FETCH di get_bodystructure e' cambiata senza il pin: {c}"
        );
    }
    // E il contenuto arriva: la summary riflette il messaggio servito.
    let text = tool_text(&run.responses[0]);
    assert!(
        text.contains("has_text_body"),
        "contratto di output assente: {text}"
    );
}

// ── Tool-to-tool contract test: the part_id that get_bodystructure hands
// over MUST be the key that download_attachment resolves, on a real
// attachment.

const SAMPLE_EML: &str = include_str!("fixtures/sample.eml");

const NESTED_RAW: &str = concat!(
    "From: alice@example.com\r\n",
    "To: bob@example.com\r\n",
    "Subject: Nested\r\n",
    "MIME-Version: 1.0\r\n",
    "Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n",
    "\r\n",
    "--OUTER\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "plain part\r\n",
    "--OUTER\r\n",
    "Content-Type: multipart/alternative; boundary=\"INNER\"\r\n",
    "\r\n",
    "--INNER\r\n",
    "Content-Type: text/plain\r\n",
    "\r\n",
    "alt plain\r\n",
    "--INNER\r\n",
    "Content-Type: text/html\r\n",
    "\r\n",
    "<b>alt html</b>\r\n",
    "--INNER--\r\n",
    "--OUTER\r\n",
    "Content-Type: application/octet-stream; name=\"data.bin\"\r\n",
    "Content-Disposition: attachment; filename=\"data.bin\"\r\n",
    "\r\n",
    "BINARY-CONTENT-0123\r\n",
    "--OUTER--\r\n",
);

/// TOOL -> TOOL su sample.eml: get_bodystructure consegna part_id "1"
/// e download_attachment("1") estrae il PDF vero.
#[tokio::test]
async fn bodystructure_part_id_feeds_download_attachment_sample() {
    let run = run_scenario_with(&[("get_bodystructure", r#"{"uid":1}"#)], true, SAMPLE_EML).await;
    let text = tool_text(&run.responses[0]);
    let actual: serde_json::Value = serde_json::from_str(&text).expect("output bodystructure JSON");
    let expected = serde_json::json!({
        "uid": 1,
        "has_text_body": true,
        "has_html_body": true,
        "attachment_count": 1,
        "attachments": [{
            "part_id": "1",
            "filename": "report.pdf",
            "content_type": "application/pdf",
            "size": 162
        }]
    });
    assert_eq!(actual, expected, "serializzazione bodystructure inattesa");
    assert!(
        text.contains("\"part_id\":\"1\""),
        "part_id sequenziale atteso: {text} | RAW: {:?}",
        run.responses[0]
    );

    let run2 = run_scenario_with(
        &[("download_attachment", r#"{"uid":1,"part_id":"1"}"#)],
        true,
        SAMPLE_EML,
    )
    .await;
    let b64 = tool_text(&run2.responses[0]);
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .expect("download in base64 valido");
    assert!(
        bytes.starts_with(b"%PDF-1.4"),
        "bytes sbagliati dal download: {:?}",
        &bytes[..bytes.len().min(20)]
    );
}

/// TOOL -> TOOL sul caso annidato (multipart dentro multipart, un
/// solo allegato in profondita'): part_id "1" -> bytes esatti.
#[tokio::test]
async fn bodystructure_part_id_feeds_download_attachment_nested() {
    let run = run_scenario_with(&[("get_bodystructure", r#"{"uid":1}"#)], true, NESTED_RAW).await;
    let text = tool_text(&run.responses[0]);
    assert!(
        text.contains("\"part_id\":\"1\"") && text.contains("data.bin"),
        "contratto part_id/filename sul nested: {text} | RAW: {:?}",
        run.responses[0]
    );

    let run2 = run_scenario_with(
        &[("download_attachment", r#"{"uid":1,"part_id":"1"}"#)],
        true,
        NESTED_RAW,
    )
    .await;
    let b64 = tool_text(&run2.responses[0]);
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .expect("download in base64 valido");
    assert_eq!(
        bytes, b"BINARY-CONTENT-0123",
        "bytes sbagliati dal download sul nested"
    );
}
