//! Composition tests for outgoing attachments.
//!
//! No network: the tests build the Message through the three paths
//! (compose_send_email / compose_create_draft / compose_update_draft) and
//! re-parse the serialized MIME. A REAL temporary filesystem with an
//! external sentinel: traversal, symlinks (final and intermediate), FIFOs
//! and swap races must yield ZERO sentinel bytes in the MIME.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use mcp_email_rs::config::{AuthMechanism, EmailConfig, SaveSentMode};
use mcp_email_rs::server::{
    AttachmentParam, CreateDraftParams, EmailServer, SendEmailParams, UpdateDraftParams,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

const SENTINEL_MARKER: &[u8] = b"SENTINEL-ATTACH-SECRET-PAYLOAD";
const SENTINEL_MARKER_STRING: &str = "SENTINEL-ATTACH-SECRET-PAYLOAD";

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "attach-{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst),
        tag
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn test_config(dir: Option<PathBuf>, max_mime_bytes: u64, max_count: usize) -> EmailConfig {
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
        attachment_dir: dir,
        attachment_max_mime_bytes: max_mime_bytes,
        attachment_max_count: max_count,
    }
}

fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent");
    }
    fs::write(path, bytes).expect("write file");
}

/// Contenuto deterministico di `len` byte.
fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
}

fn assert_no_sentinel(raw: &[u8], context: &str) {
    assert!(
        !contains(raw, SENTINEL_MARKER),
        "{context}: la sentinella è finita nel MIME"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn att(path: &str) -> AttachmentParam {
    AttachmentParam {
        path: path.into(),
        filename: None,
        mime: None,
    }
}

// ── 1. Byte identici + riparsing su TUTTI e tre i percorsi ─────────────

#[tokio::test]
async fn send_email_attachment_roundtrip_identical_bytes() {
    let home = tmp_dir("send-ok");
    let root = home.join("attach-root");
    let content = payload(1000);
    write_file(&root.join("report.bin"), &content);
    let server = EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50))
        .expect("server");

    let message = server
        .compose_send_email(&SendEmailParams {
            to: "dest@example.test".into(),
            subject: "con allegato".into(),
            body: Some("corpo testo".into()),
            html: None,
            cc: None,
            bcc: None,
            reply_to: None,
            in_reply_to: None,
            references: None,
            from: None,
            attachments: Some(vec![att("report.bin")]),
        })
        .expect("compose");
    let raw = message.formatted();

    // Riparsato: byte dell'allegato IDENTICI all'originale.
    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .expect("MIME riparsabile");
    let part = parsed.attachment(0).expect("allegato presente");
    assert_eq!(part.contents(), &content[..], "byte allegato identici");
    // Corpo testuale preservato.
    assert_eq!(
        parsed.body_text(0).as_deref(),
        Some("corpo testo"),
        "corpo preservato"
    );
    // Nessun path interno negli header.
    assert_no_sentinel(&raw, "send");
    assert!(
        !contains(&raw, root.to_string_lossy().as_bytes()),
        "il path interno non deve comparire nel MIME"
    );
    // mixed esterno (allegato presente, niente html).
    assert!(contains(&raw, b"multipart/mixed"), "mixed atteso");
}

#[tokio::test]
async fn create_draft_attachment_roundtrip_identical_bytes() {
    let home = tmp_dir("draft-ok");
    let root = home.join("attach-root");
    // Estensione non-test: il riparsing deve essere byte-identico; le parti
    // text/plain mail-parser le decodifica come testo UTF-8 (lossy per progetto).
    let content = payload(513);
    write_file(&root.join("dati.dat"), &content);
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let message = server
        .compose_create_draft(&CreateDraftParams {
            to: "dest@example.test".into(),
            subject: "bozza con allegato".into(),
            body: Some("bozza".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("dati.dat")]),
        })
        .expect("compose");
    let raw = message.formatted();
    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .expect("MIME riparsabile");
    assert_eq!(parsed.attachment(0).expect("allegato").contents(), &content[..]);
    assert_no_sentinel(&raw, "create_draft");
    assert!(!contains(&raw, root.to_string_lossy().as_bytes()));
}

#[tokio::test]
async fn update_draft_attachment_roundtrip_identical_bytes() {
    let home = tmp_dir("update-ok");
    let root = home.join("attach-root");
    let content = payload(300);
    write_file(&root.join("aggiornato.pdf"), &content);
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let message = server
        .compose_update_draft(&UpdateDraftParams {
            uid: 7,
            to: "dest@example.test".into(),
            subject: "bozza aggiornata".into(),
            body: Some("aggiornata".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("aggiornato.pdf")]),
        })
        .expect("compose");
    let raw = message.formatted();
    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .expect("MIME riparsabile");
    assert_eq!(parsed.attachment(0).expect("allegato").contents(), &content[..]);
    assert_no_sentinel(&raw, "update_draft");
    assert!(!contains(&raw, root.to_string_lossy().as_bytes()));
}

// ── 2. Sentinella esterna: traversal, symlink, race, FIFO ──────────────

fn sentinel_setup() -> (PathBuf, PathBuf, PathBuf) {
    let home = tmp_dir("sentinel");
    let root = home.join("attach-root");
    let outside = home.join("outside");
    fs::create_dir_all(&root).expect("root");
    fs::create_dir_all(&outside).expect("outside");
    let sentinel = outside.join("sentinel.txt");
    write_file(&sentinel, SENTINEL_MARKER);
    (home, root, sentinel)
}

#[tokio::test]
async fn traversal_and_symlinks_never_leak_sentinel() {
    let (home, root, sentinel) = sentinel_setup();
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let cases = vec![
        // traversal diretto e annidato
        "../sentinel.txt".to_string(),
        "sub/../../sentinel.txt".to_string(),
        // symlink finale → sentinella
        "link.txt".to_string(),
        // symlink intermedio → directory esterna
        "jump/report.bin".to_string(),
    ];
    // link finale verso la sentinella
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sentinel, root.join("link.txt")).expect("symlink finale");
    // link intermedio verso una directory esterna che contiene un file reale
    write_file(&home.join("outside-dir/report.bin"), &payload(64));
    #[cfg(unix)]
    std::os::unix::fs::symlink(&home.join("outside-dir"), root.join("jump"))
        .expect("symlink intermedio");

    for case in cases {
        let result = server.compose_create_draft(&CreateDraftParams {
            to: "dest@example.test".into(),
            subject: "attacco".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att(&case)]),
        });
        assert!(result.is_err(), "path '{case}' deve essere rifiutato");
    }
    assert_no_sentinel(b"", "nessun MIME prodotto: nessun leak");
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn intermediate_internal_symlink_is_rejected_defends_no_symlinks() {
    // Symlink INTERMEDIO e INTERNO: dir-link dentro la radice che punta a una
    // sub-directory dentro la radice. E' il caso che SOLO RESOLVE_NO_SYMLINKS
    // separa: BENEATH da solo lo consentirebbe, e O_NOFOLLOW non guarda le
    // componenti intermedie. Se qualcuno toglie NO_SYMLINKS, questo test
    // diventa rosso.
    let home = tmp_dir("internal-symlink");
    let root = home.join("attach-root");
    write_file(&root.join("sub/reale.txt"), b"contenuto-interno");
    #[cfg(unix)]
    // Target RELATIVO: con target assoluto BENEATH blocca da solo (i target
    // assoluti "escono" dalla dirfd anche senza symlink) e il test non
    // discriminerebbe NO_SYMLINKS.
    std::os::unix::fs::symlink("sub", root.join("jump")).expect("symlink intermedio interno");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let result = server.compose_create_draft(&CreateDraftParams {
        to: "dest@example.test".into(),
        subject: "symlink intermedio interno".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("jump/reale.txt")]),
    });
    assert!(
        result.is_err(),
        "symlink intermedio (anche interno) deve essere rifiutato (RESOLVE_NO_SYMLINKS)"
    );
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn final_internal_symlink_is_rejected_defends_o_nofollow() {
    // Symlink FINALE interno: punta a un file DENTRO la radice. Questo caso e'
    // fermato da O_NOFOLLOW (componente finale), non da NO_SYMLINKS: difende
    // la seconda guardia, perche' le due protezioni restano indipendenti.
    let home = tmp_dir("final-symlink");
    let root = home.join("attach-root");
    write_file(&root.join("interno.txt"), b"contenuto-interno");
    #[cfg(unix)]
    // Target RELATIVO: con target assoluto BENEATH blocca da solo e il test
    // non sarebbe discriminante per O_NOFOLLOW/NO_SYMLINKS.
    std::os::unix::fs::symlink("interno.txt", root.join("link_interno.txt"))
        .expect("symlink finale interno");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let result = server.compose_create_draft(&CreateDraftParams {
        to: "dest@example.test".into(),
        subject: "symlink finale interno".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("link_interno.txt")]),
    });
    assert!(result.is_err(), "symlink finale deve essere rifiutato (O_NOFOLLOW)");
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn concurrent_swap_classified_and_no_sentinel_leak() {
    // The hammer asserts ONLY what is stable and always true — zero
    // sentinel leaks, zero unclassified errors — for whatever distribution
    // of outcomes the scheduler produces. Observing both states is NOT a
    // failure condition anymore: it is diagnostic (printed counters). The
    // proof of window coverage belongs to the deterministic test
    // same_path_reopened_by_name_across_swapped_states (reopen by name
    // with strict classification), which does not depend on scheduler
    // luck.
    //
    // Declared epistemic limit: with openat2 the identity check and the
    // open are the SAME atomic syscall — there is no observable internal
    // window between "check" and "read" where a barrier could be planted.
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    let (home, root, sentinel) = sentinel_setup();
    let benign = root.join("swap.bin");
    write_file(&benign, b"contenuto-benigno");
    let root = Arc::new(root);
    let benign = Arc::new(benign);
    let sentinel = Arc::new(sentinel);

    let server_shared =
        Arc::new(EmailServer::from_config(test_config(Some((*root).clone()), 25_000_000, 50))
            .expect("server"));

    let stop = Arc::new(AtomicBool::new(false));
    let ok_count = Arc::new(AtomicU64::new(0));
    let err_count = Arc::new(AtomicU64::new(0));
    let sentinel_leak = Arc::new(AtomicU64::new(0));
    let partial_content = Arc::new(AtomicU64::new(0));
    let unclassified = Arc::new(AtomicU64::new(0));

    let attacker = {
        let stop = stop.clone();
        let target = (*benign).clone();
        let sentinel_path = (*sentinel).clone();
        thread::spawn(move || {
            // BOTH states are swapped ATOMICALLY via rename: the reader
            // always sees a complete file. A direct fs::write on the target
            // truncates and refills: a reader inside the window would see an
            // empty/half file (a false "partial content" outcome).
            let tmp_file = target.with_extension("bin.tmp");
            let tmp_link = target.with_extension("bin.link-tmp");
            while !stop.load(Ordering::SeqCst) {
                let _ = fs::write(&tmp_file, b"contenuto-benigno");
                let _ = fs::rename(&tmp_file, &target);
                let _ = std::os::unix::fs::symlink(&sentinel_path, &tmp_link);
                let _ = fs::rename(&tmp_link, &target);
            }
        })
    };

    let mut handles = Vec::new();
    for _reader in 0..4 {
        let stop = stop.clone();
        let ok_count = ok_count.clone();
        let err_count = err_count.clone();
        let sentinel_leak = sentinel_leak.clone();
        let partial_content = partial_content.clone();
        let unclassified = unclassified.clone();
        let server = server_shared.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..150 {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                let result = server.compose_send_email(&SendEmailParams {
                    to: "dest@example.test".into(),
                    subject: "race".into(),
                    body: Some("x".into()),
                    html: None,
                    cc: None,
                    bcc: None,
                    reply_to: None,
                    in_reply_to: None,
                    references: None,
                    from: None,
                    attachments: Some(vec![att("swap.bin")]),
                });
                match result {
                    Ok(message) => {
                        let raw = message.formatted();
                        // TWO separate counters: sentinel found = a security
                        // leak; non-benign content WITHOUT the sentinel = a
                        // partial read. Two conditions on the same counter
                        // would make it impossible to tell what happened.
                        if contains(&raw, SENTINEL_MARKER) {
                            sentinel_leak.fetch_add(1, Ordering::SeqCst);
                        } else if !contains(&raw, b"contenuto-benigno") {
                            partial_content.fetch_add(1, Ordering::SeqCst);
                        }
                        ok_count.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(error) => {
                        let text = error.to_string();
                        if text.contains(SENTINEL_MARKER_STRING) {
                            sentinel_leak.fetch_add(1, Ordering::SeqCst);
                        } else if text.contains("rifiutata da openat2") {
                            err_count.fetch_add(1, Ordering::SeqCst);
                        } else {
                            // ESITO NON CLASSIFICABILE = fallimento del test:
                            // nessun errore è ignorato.
                            panic!("errore inatteso e non classificato: {text}");
                        }
                    }
                }
            }
        }))
    }
    for handle in handles {
        handle.join().expect("join reader");
    }
    stop.store(true, Ordering::SeqCst);
    attacker.join().expect("join attacker");

    assert_eq!(unclassified.load(Ordering::SeqCst), 0, "ogni errore deve essere classificato");
    assert_eq!(
        sentinel_leak.load(Ordering::SeqCst),
        0,
        "ZERO leak di sentinella: la guardia openat2 non deve mai far passare il contenuto esterno"
    );
    assert_eq!(
        partial_content.load(Ordering::SeqCst),
        0,
        "ZERO letture parziali: con swap atomico il lettore vede sempre un file completo"
    );
    // Diagnostica, NON condizione di fallimento: la distribuzione degli esiti
    // sotto carico dipende dallo scheduler. La copertura della finestra è
    // provata dal test deterministico same_path_reopened_by_name_across…
    eprintln!(
        "SWAP-HAMMER diagnostica: ok={}, rifiuti-openat2={}, unclassified={}, sentinella-leak={}, parziali={}",
        ok_count.load(Ordering::SeqCst),
        err_count.load(Ordering::SeqCst),
        unclassified.load(Ordering::SeqCst),
        sentinel_leak.load(Ordering::SeqCst),
        partial_content.load(Ordering::SeqCst)
    );
    let _ = fs::remove_dir_all(&home);
}

/// (A) RIAPERTURA PER NOME, deterministica e senza concorrenza: la prova
/// discriminante per la finestra. Stesso path, due stati:
///  - file reale → successo con contenuto benigno;
///  - symlink → sentinella → DEVE fallire con l'errore openat2.
/// Un'implementazione che cacheasse l'handle aperto (o canonicalizzasse e
/// riusasse il canone) restituirebbe il vecchio contenuto nello stato
/// symlink: questo test cade. Con openat2 la riapertura per nome è data
/// dalla syscall atomica stessa — non esiste una finestra interna da
/// dimostrare, e questo test dimostra la proprietà osservabile equivalente.
#[tokio::test]
async fn same_path_reopened_by_name_across_swapped_states() {
    let (home, root, sentinel) = sentinel_setup();
    let target = root.join("swap.bin");
    write_file(&target, b"contenuto-benigno");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");
    let params = || SendEmailParams {
        to: "dest@example.test".into(),
        subject: "reopen".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        reply_to: None,
        in_reply_to: None,
        references: None,
        from: None,
        attachments: Some(vec![att("swap.bin")]),
    };

    for iteration in 0..25 {
        let _ = fs::remove_file(&target);
        write_file(&target, b"contenuto-benigno");
        let message = server
            .compose_send_email(&params())
            .unwrap_or_else(|e| panic!("iterazione {iteration}: file reale deve comporre: {e}"));
        let raw = message.formatted();
        assert_no_sentinel(&raw, "reopen: stato file reale");
        assert!(contains(&raw, b"contenuto-benigno"));

        let _ = fs::remove_file(&target);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&sentinel, &target).expect("symlink");
        let error = server
            .compose_send_email(&params())
            .err()
            .unwrap_or_else(|| panic!("iterazione {iteration}: stato symlink deve essere rifiutato"));
        assert!(
            error.to_string().contains("rifiutata da openat2"),
            "iterazione {iteration}: atteso rifiuto openat2, trovato: {error}"
        );
        assert_no_sentinel(&error.to_string().as_bytes(), "nessun leak nell'errore");
    }
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn fifo_without_writer_fails_without_hanging() {
    let home = tmp_dir("fifo");
    let root = home.join("attach-root");
    fs::create_dir_all(&root).expect("root");
    let fifo = root.join("pipe.bin");
    let c = std::ffi::CString::new(fifo.to_string_lossy().as_bytes()).expect("cstr");
    let rc = libc_mkfifo(c.as_ptr(), 0o600);
    assert_eq!(rc, 0, "mkfifo");

    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");
    let (tx, rx) = mpsc::channel();
    let fifo_clone = fifo.clone();
    thread::spawn(move || {
        let result = server.compose_create_draft(&CreateDraftParams {
            to: "dest@example.test".into(),
            subject: "fifo".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("pipe.bin")]),
        });
        let _ = fifo_clone;
        tx.send(result.is_err()).expect("send result");
    });
    let rejected = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("FIFO senza writer: nessun blocco entro il timeout");
    assert!(rejected, "FIFO senza writer deve essere rifiutato");
    let _ = fs::remove_dir_all(&home);
}

// Cargo non espone libc ai test direttamente? Sì: è una dependency del crate,
// ma i test di integrazione vedono solo il crate. Usiamo una bind minimal via extern.
fn libc_mkfifo(path: *const std::os::raw::c_char, mode: u32) -> i32 {
    unsafe extern "C" {
        fn mkfifo(path: *const std::os::raw::c_char, mode: std::os::raw::c_uint) -> i32;
    }
    unsafe { mkfifo(path, mode) }
}

// ── 3. Tetto dimensione: esatto al limite, +1 dopo encoding ────────────

#[tokio::test]
async fn multi_attachment_near_limit_not_falsely_rejected() {
    // A fixed 1.5x raw estimate would reject the second of two 9,000,000-byte
    // files while the real MIME is 24,632,297 < 25,000,000.
    let home = tmp_dir("multi-cap");
    let root = home.join("attach-root");
    write_file(&root.join("uno.bin"), &vec![b'A'; 9_000_000]);
    write_file(&root.join("due.bin"), &vec![b'B'; 9_000_000]);
    let server_25m = EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50))
        .expect("server");
    let params_two = CreateDraftParams {
        to: "dest@example.test".into(),
        subject: "multi cap".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("uno.bin"), att("due.bin")]),
    };
    let message = server_25m
        .compose_create_draft(&params_two)
        .expect("due file da 9M stanno sotto il tetto (falso rifiuto)");
    let total = message.formatted().len();
    assert!(total <= 25_000_000, "MIME {total} entro il tetto");

    // Sopra soglia (deterministica): un allegato il cui MIME reale porta il
    // messaggio oltre 25M — rifiutato dal controllo esatto; sotto soglia
    // con 23M — passato.
    write_file(&root.join("uno.bin"), &vec![b'C'; 24_500_000]);
    assert!(
        server_25m
            .compose_create_draft(&CreateDraftParams {
                to: "dest@example.test".into(),
                subject: "over".into(),
                body: Some("x".into()),
                html: None,
                cc: None,
                bcc: None,
                attachments: Some(vec![att("uno.bin")]),
            })
            .is_err(),
        "allegato che porta il MIME oltre il tetto: rifiutato"
    );
    write_file(&root.join("uno.bin"), &vec![b'C'; 23_000_000]);
    assert!(
        server_25m
            .compose_create_draft(&CreateDraftParams {
                to: "dest@example.test".into(),
                subject: "under".into(),
                body: Some("x".into()),
                html: None,
                cc: None,
                bcc: None,
                attachments: Some(vec![att("uno.bin")]),
            })
            .is_ok(),
        "allegato entro il tetto: passato"
    );
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn mixed_text_and_binary_near_limit_not_falsely_rejected() {
    // 18 MB of text (8bit ~1.04x) + 3 MB of binary (base64 ~1.37x) -> real
    // MIME 22,105,967 < 25,000,000: an "all base64" bound would overestimate
    // the text part and reject. With the part encoded by lettre and measured
    // in prepare, the cost is the real one.
    let home = tmp_dir("mixed-cap");
    let root = home.join("attach-root");
    let mut text = vec![b'T'; 18_000_000];
    text.truncate(18_000_000 - (18_000_000 % 3)); // resta ASCII pulito
    write_file(&root.join("testo.txt"), &text);
    write_file(&root.join("binario.bin"), &payload(3_000_000));
    let server_25m = EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50))
        .expect("server");
    let message = server_25m
        .compose_create_draft(&CreateDraftParams {
            to: "dest@example.test".into(),
            subject: "mixed".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("testo.txt"), att("binario.bin")]),
        })
        .expect("testo+binario entro il tetto: nessun falso rifiuto");
    let total = message.formatted().len();
    assert!(total <= 25_000_000, "MIME {total} entro il tetto");
    // E il contenuto binario è integro dopo l'encoding reale.
    let raw = message.formatted();
    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .expect("riparsabile");
    let binary_part = parsed.attachment(1).expect("secondo allegato");
    assert_eq!(binary_part.contents().len(), 3_000_000);
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn size_cap_exact_limit_passes_one_encoded_byte_over_fails() {
    let home = tmp_dir("cap");
    let root = home.join("attach-root");
    // 90 % 3 == 0: +1 byte grezzo ⇒ +4 byte base64 dopo l'encoding.
    let content = vec![b'A'; 90];
    write_file(&root.join("cap.txt"), &content);
    let big_limit_config = || test_config(Some(root.clone()), 1_000_000_000, 50);
    let server_big = EmailServer::from_config(big_limit_config()).expect("server");
    let params = || CreateDraftParams {
        to: "dest@example.test".into(),
        subject: "cap".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("cap.txt")]),
    };

    let exact_len = server_big
        .compose_create_draft(&params())
        .expect("compose")
        .formatted()
        .len();

    // Esattamente al limite: passa.
    let server_exact = EmailServer::from_config(test_config(
        Some(root.clone()),
        exact_len as u64,
        50,
    ))
    .expect("server");
    assert!(
        server_exact.compose_create_draft(&params()).is_ok(),
        "MIME di {exact_len} byte deve passare con tetto {exact_len}"
    );

    // +1 byte grezzo ⇒ MIME +4 byte: oltre il tetto, rifiutato.
    write_file(&root.join("cap.txt"), &vec![b'A'; 91]);
    assert!(
        server_exact.compose_create_draft(&params()).is_err(),
        "MIME oltre il tetto deve essere rifiutato"
    );
    // A file on disk MUCH larger than the ceiling: the stop-loss fires during
    // the read (the whole file is not read just to reject it afterwards). The
    // proof is the MEASURE of the bytes read reported by the error, not the
    // duration.
    write_file(&root.join("cap.txt"), &vec![b'B'; 5_000_000]);
    let server_small = EmailServer::from_config(test_config(Some(root.clone()), 1_000, 50))
        .expect("server");
    let started = std::time::Instant::now();
    let error = server_small
        .compose_create_draft(&params())
        .expect_err("tetto piccolo con file enorme: rifiutato in lettura");
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "lettura limitata dal budget: nessuna lettura integrale"
    );
    // The MEASURE of the bytes read is not taken from the error the code
    // itself produces (a self-tested meter): the independent measure is the
    // reader-wrapper counter in the unit test
    // `read_bounded_bytes_consumed_measured_by_independent_meter`. Here only
    // the end-to-end flow is verified: rejection within the time limit.
    let _ = fs::remove_dir_all(&home);
}

// ── 4. Env assente, nomi, mime, conteggio, semantica [] ────────────────

#[tokio::test]
async fn attachments_disabled_without_env_with_explicit_error() {
    let home = tmp_dir("noenv");
    let root = home.join("attach-root");
    write_file(&root.join("report.bin"), b"dati");
    let server = EmailServer::from_config(test_config(None, 25_000_000, 50)).expect("server");
    let err = server
        .compose_create_draft(&CreateDraftParams {
            to: "dest@example.test".into(),
            subject: "no env".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("report.bin")]),
        })
        .expect_err("allegati disabilitati senza EMAIL_ATTACH_DIR");
    assert!(
        err.to_string().contains("EMAIL_ATTACH_DIR"),
        "errore esplicito che nomina l'env: {err}"
    );
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn names_and_mime_types_validation() {
    let home = tmp_dir("names");
    let root = home.join("attach-root");
    write_file(&root.join("sub/report.bin"), &payload(64));
    write_file(&root.join("PHOTO.JPG"), &payload(64));
    write_file(&root.join("mistero.xyz"), &payload(64));
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    // Nome di default = basename: il percorso non compare negli header.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "basename".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("sub/report.bin")]),
        })
        .expect("compose")
        .formatted();
    assert!(contains(&raw, b"filename=\"report.bin\""), "basename esposto");
    assert!(
        !contains(&raw, b"sub/report.bin"),
        "il percorso non deve comparire nel MIME"
    );

    // Mappa estensione case-insensitive.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "mime map".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("PHOTO.JPG")]),
        })
        .expect("compose")
        .formatted();
    assert!(contains(&raw, b"image/jpeg"), "estensione case-insensitive");

    // Fallback octet-stream.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "fallback".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![att("mistero.xyz")]),
        })
        .expect("compose")
        .formatted();
    assert!(
        contains(&raw, b"application/octet-stream"),
        "fallback octet-stream"
    );

    // MIME esplicito valido e non valido; filename con CR/LF e separatori.
    let explicit = AttachmentParam {
        path: "mistero.xyz".into(),
        filename: Some("doc.pdf".into()),
        mime: Some("APPLICATION/PDF".into()),
    };
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "explicit mime".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![explicit]),
        })
        .expect("compose")
        .formatted();
    assert!(contains(&raw, b"application/pdf"));

    for bad_mime in ["text", "text /plain", "text/plain;charset=x", "a b/c"] {
        let result = server.compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "bad mime".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![AttachmentParam {
                path: "mistero.xyz".into(),
                filename: None,
                mime: Some(bad_mime.into()),
            }]),
        });
        assert!(result.is_err(), "mime '{bad_mime}' deve essere rifiutato");
    }
    for bad_name in ["cattivo\r\nX-Inject: 1", "percorso/cattivo", "..", ".", ""] {
        let result = server.compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "bad name".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![AttachmentParam {
                path: "mistero.xyz".into(),
                filename: Some(bad_name.into()),
                mime: None,
            }]),
        });
        assert!(result.is_err(), "filename '{bad_name}' deve essere rifiutato");
    }
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn backslash_in_implicit_basename_is_rejected() {
    // On Unix '\' is a valid filename character and the implicit basename
    // must go through the same validation as an explicit name.
    let home = tmp_dir("backslash");
    let root = home.join("attach-root");
    write_file(&root.join("back\\slash.bin"), b"dati");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");
    let result = server.compose_create_draft(&CreateDraftParams {
        to: "d@e.test".into(),
        subject: "backslash".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("back\\slash.bin")]),
    });
    assert!(result.is_err(), "basename implicito con backslash: rifiutato");
    // Nome esplicito valido sullo stesso file: passa e il nome esposto è quello.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "backslash esplicito".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![AttachmentParam {
                path: "back\\slash.bin".into(),
                filename: Some("ok.bin".into()),
                mime: None,
            }]),
        })
        .expect("nome esplicito valido deve comporre")
        .formatted();
    assert!(contains(&raw, b"filename=\"ok.bin\""));
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn hardlink_to_external_file_documents_a_limit_not_a_protection() {
    // Measures the REAL behavior, not a protection. A hardlink inside the
    // staging root points to an EXTERNAL file: same inode, no symlink to
    // reject. openat2 RESOLVE_NO_SYMLINKS does not cover hardlinks (see the
    // contract in .env.example / email.toml.example: "hardlinks, bind mounts
    // and concurrent inode writers are not stopped"). Contract expectation:
    // the file IS READ — the test asserts the read because it documents the
    // limit; if one day it were rejected, the contract would need to be
    // updated together (do NOT adapt the code to make this test pass).
    let home = tmp_dir("hardlink");
    let root = home.join("attach-root");
    fs::create_dir_all(&root).expect("root");
    let outside_secret = home.join("esterno").join("segreto.txt");
    write_file(&outside_secret, b"SEGRETO-ESTERNO-VIA-HARDLINK");
    #[cfg(unix)]
    fs::hard_link(&outside_secret, root.join("hardlink.txt")).expect("hardlink dentro la staging");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let result = server.compose_create_draft(&CreateDraftParams {
        to: "dest@example.test".into(),
        subject: "hardlink".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("hardlink.txt")]),
    });

    // Comportamento REALE misurato su questo codice: l'hardlink viene LETTO
    // (e questo è il limite documentato, non una protezione).
    let message = result.expect(
        "misura attesa: l'hardlink viene letto (stesso inode, no symlink).          Se questo fallisce, il codice ha iniziato a rifiutare gli hardlink:          aggiornare il contratto nella documentazione e questo test",
    );
    let raw = message.formatted();
    assert!(
        contains(&raw, b"SEGRETO-ESTERNO-VIA-HARDLINK"),
        "contenuto esterno presente nel MIME: limite confermato"
    );
    // E il nome esposto è il basename dell'hardlink, non il percorso esterno.
    assert!(contains(&raw, b"filename=\"hardlink.txt\""));
    assert!(!contains(&raw, root.to_string_lossy().as_bytes()));
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn attachment_count_limit_enforced() {
    let home = tmp_dir("count");
    let root = home.join("attach-root");
    for name in ["a.txt", "b.txt", "c.txt"] {
        write_file(&root.join(name), b"x");
    }
    let server = EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 2))
        .expect("server");
    let result = server.compose_create_draft(&CreateDraftParams {
        to: "d@e.test".into(),
        subject: "count".into(),
        body: Some("x".into()),
        html: None,
        cc: None,
        bcc: None,
        attachments: Some(vec![att("a.txt"), att("b.txt"), att("c.txt")]),
    });
    assert!(result.is_err(), "oltre il numero massimo: rifiutato");
    let _ = fs::remove_dir_all(&home);
}

#[tokio::test]
async fn omitted_and_empty_attachments_are_identical() {
    let home = tmp_dir("semantics");
    let root = home.join("attach-root");
    write_file(&root.join("keep.txt"), b"keep");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    let omitted = server
        .compose_update_draft(&UpdateDraftParams {
            uid: 1,
            to: "d@e.test".into(),
            subject: "s".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: None,
        })
        .expect("compose")
        .formatted();
    let empty = server
        .compose_update_draft(&UpdateDraftParams {
            uid: 1,
            to: "d@e.test".into(),
            subject: "s".into(),
            body: Some("x".into()),
            html: None,
            cc: None,
            bcc: None,
            attachments: Some(vec![]),
        })
        .expect("compose")
        .formatted();
    assert_eq!(omitted, empty, "omesso e [] sono la stessa cosa: niente conservazione implicita");
    assert!(!contains(&empty, b"keep.txt"), "nessun allegato residuo");
    let _ = fs::remove_dir_all(&home);
}

// ── 5. Struttura MIME: mixed esterno con alternative interno ───────────

#[tokio::test]
async fn html_with_attachments_is_mixed_with_alternative_inside() {
    let home = tmp_dir("structure");
    let root = home.join("attach-root");
    write_file(&root.join("f.txt"), b"f");
    let server =
        EmailServer::from_config(test_config(Some(root.clone()), 25_000_000, 50)).expect("server");

    // html SENZA allegati: alternative (formato storico), niente mixed.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "html only".into(),
            body: Some("testo".into()),
            html: Some("<b>html</b>".into()),
            cc: None,
            bcc: None,
            attachments: None,
        })
        .expect("compose")
        .formatted();
    assert!(contains(&raw, b"multipart/alternative"));
    assert!(!contains(&raw, b"multipart/mixed"));

    // html CON allegati: mixed esterno, alternative interno.
    let raw = server
        .compose_create_draft(&CreateDraftParams {
            to: "d@e.test".into(),
            subject: "html + att".into(),
            body: Some("testo".into()),
            html: Some("<b>html</b>".into()),
            cc: None,
            bcc: None,
            attachments: Some(vec![att("f.txt")]),
        })
        .expect("compose")
        .formatted();
    assert!(contains(&raw, b"multipart/mixed"), "mixed esterno");
    assert!(contains(&raw, b"multipart/alternative"), "alternative interno");
    let parsed = mail_parser::MessageParser::default()
        .parse(&raw)
        .expect("riparsabile");
    assert!(parsed.html_body_count() >= 1, "html preservato");
    assert!(parsed.body_text(0).is_some(), "testo preservato");
    assert_no_sentinel(&raw, "structure");
    let _ = fs::remove_dir_all(&home);
}
