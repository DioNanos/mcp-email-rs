//! OUTGOING attachment staging (`attachments` of send_email / create_draft /
//! update_draft): safe path resolution, bounded reading and MIME part
//! construction.
//!
//! Security model:
//! - the root is the dedicated `EMAIL_ATTACH_DIR` env, read at load time in
//!   [`crate::config::EmailConfig`]; **missing env => attachments disabled
//!   with an explicit error**: never a fallback to cwd or home (unlike
//!   `download_base_dir` in `server.rs`, which only serves READS);
//! - requested paths must be RELATIVE: absolute paths, `..` and symlinks
//!   (intermediate ones included) are rejected;
//! - verification and reading happen on the SAME fd: `openat2` with
//!   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` against the root — no TOCTOU
//!   window between canonicalize and read; a kernel without `openat2`
//!   (ENOSYS/EPERM/EINVAL) => a closed error, no permissive fallback;
//! - `O_NONBLOCK | O_NOFOLLOW`: FIFOs/sockets/devices are rejected via
//!   `fstat` without blocking reads; only regular files are accepted;
//! - the ceiling is measured on the SERIALIZED MIME (default 25,000,000
//!   bytes, headers and transfer encoding included): a stop-loss during the
//!   read plus an exact check on the composed message.

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::path::Path;

use lettre::message::header::ContentType;
use lettre::message::{Attachment as LettreAttachment, MultiPart, SinglePart};

use crate::error::EmailError;

/// Tetto predefinito sul MIME serializzato dell'intero messaggio, in byte.
pub const DEFAULT_MAX_MIME_BYTES: u64 = 25_000_000;

/// Numero predefinito massimo di allegati per messaggio.
pub const DEFAULT_MAX_COUNT: usize = 50;

/// Stop-loss oltre il tetto durante la lettura di un singolo file: permette di
/// NON leggere file molto più grandi del budget, lasciando al controllo ESATTO
/// sul MIME serializzato l'ultima parola (nessun falso rifiuto al limite).
const READ_SLACK_BYTES: u64 = 64 * 1024;

/// Riserva per gli header del messaggio, dedotta PRIMA di leggere qualsiasi
/// allegato (la guardia sugli header precede il builder).
const MESSAGE_HEADERS_RESERVE_BYTES: u64 = 4 * 1024;

/// Overhead per allegato che il budget non vede nella parte (boundary line
/// e CRLF del multipart).
const PART_BOUNDARY_OVERHEAD_BYTES: u64 = 128;

/// An attachment that has been read, validated and ENCODED by lettre, ready
/// for `compose_body`. The part is pre-built here so the budget is derived
/// from the REAL size of the encoded part: the effective encoding depends on
/// the content — 8bit ~1.04x for clean text, base64+wrapping ~1.3685x for
/// binary — and a fixed estimate on the raw bytes either overestimates and
/// rejects valid messages, or underestimates and fails to limit.
#[derive(Debug, Clone)]
pub struct PreparedAttachment {
    /// Nome esposto nell'email: solo basename o nome esplicito validato.
    pub filename: String,
    /// MIME validato (`tipo/sottotipo`, token RFC).
    pub content_type: String,
    /// Byte grezzi del file, per ispezione/diagnostica.
    pub body: Vec<u8>,
    /// Parte MIME già codificata da lettre: la sua dimensione serializzata
    /// è la misura REALE usata per il budget.
    pub part: SinglePart,
}

/// Input di [`prepare`]: una richiesta di allegato cosi' com'e' arrivata al tool.
#[derive(Debug, Clone, Copy)]
pub struct AttachmentInput<'a> {
    pub path: &'a str,
    pub filename: Option<&'a str>,
    pub mime: Option<&'a str>,
}

/// Limiti applicati a una richiesta di allegati.
#[derive(Debug, Clone, Copy)]
pub struct AttachmentLimits {
    /// Tetto sul MIME serializzato dell'intero messaggio (byte).
    pub max_mime_bytes: u64,
    /// Numero massimo di allegati per messaggio.
    pub max_count: usize,
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$&^_.+-".contains(c)
}

/// Valida un MIME esplicito `tipo/sottotipo` (token RFC, niente parametri,
/// niente spazi) e lo restituisce normalizzato in minuscolo.
pub fn validate_mime(mime: &str) -> Result<String, EmailError> {
    let reject = |why: &str| EmailError::Other(format!("mime allegato non valido: {why}"));
    let Some((ty, sub)) = mime.split_once('/') else {
        return Err(reject(&format!(
            "atteso 'tipo/sottotipo' senza parametri, trovato '{mime}'"
        )));
    };
    let token_ok = |s: &str| !s.is_empty() && s.chars().all(is_token_char);
    if !token_ok(ty) || !token_ok(sub) {
        return Err(reject(&format!(
            "'{mime}' non è due token RFC separati da '/'; spazi e parametri non sono ammessi"
        )));
    }
    Ok(mime.to_ascii_lowercase())
}

/// Mappa estensione → MIME, case-insensitive, con fallback esplicito.
pub fn mime_for_extension(path: &str) -> &'static str {
    let ext = Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");
    match ext.to_ascii_lowercase().as_str() {
        "pdf" => "application/pdf",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
}

/// Nome esposto nell'email: il nome esplicito validato, oppure il basename del
/// path. Rifiuta vuoto, `.`, `..`, separatori di percorso e CR/LF/NUL
/// (iniezione di header).
pub fn exposed_name(requested: Option<&str>, path: &str) -> Result<String, EmailError> {
    let reject = |why: String| EmailError::Other(format!("filename allegato non valido: {why}"));
    // IDENTICAL validation for an explicit name and an implicit basename:
    // on Unix '\' is a valid filename character and a basename derived from
    // the path can contain it — it must never end up in the headers.
    fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(format!("nome vuoto o ambiguo: '{name}'"));
        }
        if name
            .chars()
            .any(|c| matches!(c, '/' | '\\' | '\r' | '\n' | '\0'))
        {
            return Err(format!(
                "'{name}' contiene separatori di percorso o CR/LF: mai un percorso, solo un nome"
            ));
        }
        Ok(())
    }
    match requested {
        Some(name) => {
            validate_name(name).map_err(reject)?;
            Ok(name.to_string())
        }
        None => {
            let base = Path::new(path)
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or_else(|| reject(format!("impossibile ricavare il basename da '{path}'")))?;
            validate_name(base).map_err(reject)?;
            Ok(base.to_string())
        }
    }
}

/// Il path richiesto deve essere RELATIVO e senza risalite: rifiuta il vuoto,
/// gli assoluti, `..` e le radici/prefissi non-Unix. (`.` è tollerato: anche
/// se passasse, openat2 RESOLVE_BENEATH lo confina nella radice.)
fn validate_relative(path: &str) -> Result<(), EmailError> {
    let reject = |why: &str| {
        Err::<(), _>(EmailError::Other(format!(
            "path allegato '{path}' rifiutato: {why}"
        )))
    };
    if path.is_empty() {
        return reject("path vuoto");
    }
    if path.starts_with('/') {
        return reject("solo path relativi dentro EMAIL_ATTACH_DIR, assoluti rifiutati");
    }
    for comp in Path::new(path).components() {
        match comp {
            std::path::Component::ParentDir => return reject("'..' non è ammesso"),
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return reject("componente non relativa")
            }
            _ => {}
        }
    }
    Ok(())
}

/// Apre `relative` sotto la radice con openat2 atomica:
/// `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS` rifiuta nel kernel ogni fuga dalla
/// radice e ogni symlink (anche intermedi). La verifica e la lettura usano lo
/// STESSO fd restituito: nessuna finestra TOCTOU.
///
/// `O_NONBLOCK` garantisce che l'apertura di una FIFO senza writer non blocchi;
/// il `fstat` subito dopo rifiuta tutto ciò che non sia un file regolare.
fn open_regular_beneath(root: &Path, relative: &str) -> Result<File, EmailError> {
    open_regular_beneath_with(
        root,
        relative,
        (libc::RESOLVE_BENEATH | libc::RESOLVE_NO_SYMLINKS) as u64,
    )
}

/// Variante con flag `resolve` espliciti: serve ai test per il controllo
/// positivo («senza BENEATH la sentinella è leggibile») senza toccare la
/// produzione.
fn open_regular_beneath_with(root: &Path, relative: &str, resolve: u64) -> Result<File, EmailError> {
    let dir = File::open(root).map_err(|e| {
        EmailError::Config(format!(
            "EMAIL_ATTACH_DIR '{}' non apribile: {e}",
            root.display()
        ))
    })?;
    let c_path = CString::new(relative.as_bytes())
        .map_err(|_| EmailError::Other("path allegato contiene NUL".into()))?;
    // Stesso layout di `struct open_how` (linux/openat2.h): libc la dichiara
    // #[non_exhaustive] e non la lascia costruire fuori dal crate.
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    let how = OpenHow {
        flags: (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dir.as_raw_fd(),
            c_path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            // Kernel senza openat2 o con seccomp/filtri: errore CHIUSO, mai un
            // ripiego su open() classico.
            Some(libc::ENOSYS) | Some(libc::EPERM) | Some(libc::EINVAL) => {
                EmailError::Config(format!(
                    "openat2 non disponibile su questo kernel (errno {}): \
                     allegati disabilitati (errore chiuso, nessun fallback permissivo)",
                    err.raw_os_error().unwrap_or(0)
                ))
            }
            _ => EmailError::Other(format!(
                "apertura allegato '{relative}' rifiutata da openat2: {err}"
            )),
        });
    }
    // Proprietà del fd passa a File (chiusura automatica anche sui rami di errore).
    let file = unsafe { File::from_raw_fd(fd as std::os::fd::RawFd) };
    let meta = file.metadata().map_err(|e| {
        EmailError::Other(format!("fstat su '{relative}' fallito: {e}"))
    })?;
    if !meta.is_file() {
        return Err(EmailError::Other(format!(
            "'{relative}' non è un file regolare: FIFO/socket/device rifiutati senza leggere"
        )));
    }
    Ok(file)
}

/// TEST ONLY: a call barrier between the open and the read. It sits outside
/// the syscall, so openat2's atomicity cannot block it: the test uses it to
/// plant a swap at the exact point where a "reopen-by-name" implementation
/// would do damage. It does not exist in production (#[cfg(test)]) and the
/// behavior does not change.
#[cfg(test)]
pub(crate) static AFTER_OPEN_HOOK: std::sync::Mutex<Option<Box<dyn FnMut() + Send>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn run_after_open_hook() {
    // Monouso (take): la barriera scatta una sola volta e non inquina i
    // prepare successivi.
    if let Some(mut hook) = AFTER_OPEN_HOOK.lock().expect("hook lock").take() {
        hook();
    }
}

/// Legge al massimo `max_raw` byte (fermandosi oltre: il file può crescere
/// durante l'operazione) e rifiuta tutto ciò che ecceda. Generica su `Read`
/// così il metro dei byte consumati può essere costruito DAL TEST (contatore
/// indipendente), non solo dal messaggio d'errore del codice.
fn read_bounded<R: Read>(mut reader: R, max_raw: u64, what: &str) -> Result<Vec<u8>, EmailError> {
    let cap = usize::try_from(max_raw)
        .unwrap_or(usize::MAX)
        .saturating_add(1);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 65_536];
    loop {
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            return Ok(buf);
        }
        if buf.len() + n > cap {
            return Err(EmailError::Other(format!(
                "'{what}' supera il budget di lettura consentito: interrotta dopo {} byte                  (tetto MIME serializzato)",
                buf.len()
            )));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Legge e valida tutti gli allegati di una richiesta.
///
/// Errori espliciti per: env radice non configurata (chi chiama già filtra, ma
/// la funzione resta chiusa anche da sola), troppi allegati, path relativi
/// malformati, symlink/escape, file non regolari, budget esaurito.
pub fn prepare<'a>(
    dir: &Path,
    inputs: impl IntoIterator<Item = AttachmentInput<'a>>,
    limits: AttachmentLimits,
) -> Result<Vec<PreparedAttachment>, EmailError> {
    let inputs: Vec<AttachmentInput<'a>> = inputs.into_iter().collect();
    if inputs.len() > limits.max_count {
        return Err(EmailError::Other(format!(
            "troppe richieste di allegati: {} > limite {} per messaggio",
            inputs.len(),
            limits.max_count
        )));
    }
    // La guardia sugli header DEVE venire prima del builder: si reserva
    // subito il budget dei header del messaggio (From/To/Subject + boundary),
    // invece di scoprirli dopo aver composto. Riserva generosa (4 KiB): un
    // header entro i limiti usuali ci sta; se sfora, il controllo esatto
    // finale resta l'autorità.
    let mut remaining = limits
        .max_mime_bytes
        .saturating_sub(MESSAGE_HEADERS_RESERVE_BYTES);
    let mut prepared = Vec::with_capacity(inputs.len());
    for input in inputs {
        validate_relative(input.path)?;
        let filename = exposed_name(input.filename, input.path)?;
        let content_type = match input.mime {
            Some(explicit) => validate_mime(explicit)?,
            None => mime_for_extension(input.path).to_string(),
        };
        // Stop-loss: the real encoding depends on the CONTENT — lettre picks
        // 8bit (~1.04x) for clean 7-bit text and base64 with CRLF wrapping
        // (~1.3685x) for binary — so a fixed estimate on the raw bytes either
        // falsely rejects or fails to limit. Correct scheme:
        //  - the read ceiling for a file is the RESIDUAL budget + slack:
        //    a valid file consumes at most ~0.96x of its MIME cost (8bit is
        //    the minimum ratio) and the cost is always >= raw, so
        //    raw <= residual never truncates a message within the cap;
        //  - the amount deducted from the budget is the exact WORST-CASE
        //    bound (base64 with wrapping, computed from the buffer read) —
        //    never an underestimate => the estimated residual stays <= the
        //    real one;
        //  - the EXACT check remains on the serialized message (finalize in
        //    server.rs). Bounded read: never more than ~budget+slack per
        //    file, so no unbounded allocations.
        let max_raw = remaining.saturating_add(READ_SLACK_BYTES);
        let file = open_regular_beneath(dir, input.path)?;
        #[cfg(test)]
        run_after_open_hook();
        let body = read_bounded(file, max_raw, input.path)?;
        // La parte viene CODIFICATA SUBITO da lettre: la sua dimensione
        // serializzata è la misura REALE (non una stima) del suo costo nel
        // MIME, qualunque encoding il contenuto richieda (7bit/8bit/QP/base64).
        let part = LettreAttachment::new(filename.clone()).body(body.clone(), {
            ContentType::parse(&content_type).expect("MIME validato in prepare()")
        });
        let part_size = part.formatted().len() as u64 + PART_BOUNDARY_OVERHEAD_BYTES;
        remaining = remaining.saturating_sub(part_size);
        prepared.push(PreparedAttachment {
            filename,
            content_type,
            body,
            part,
        });
    }
    Ok(prepared)
}

/// Corpo composto pronto per essere finalizzato su `Message::builder`.
pub enum ComposedBody {
    /// No attachments, text only: `singlepart` (the historical format).
    Single(SinglePart),
    /// `multipart/alternative` (html without attachments) or an outer
    /// `multipart/mixed` with an inner `alternative`/text plus the attachments.
    Multi(MultiPart),
}

/// UNA funzione per i TRE percorsi di costruzione (send_email, create_draft,
/// update_draft): testo + html opzionale + allegati.
///
/// - nessun allegato, nessun html → `singlepart` testo (formato storico);
/// - nessun allegato, html → `multipart/alternative` (formato storico);
/// - allegati → `multipart/mixed` esterno con (alternative | testo) interno e
///   una parte `Attachment` per ogni allegato.
pub fn compose_body(
    body: String,
    html: Option<String>,
    attachments: &[PreparedAttachment],
) -> ComposedBody {
    let text_part = SinglePart::builder()
        .header(ContentType::TEXT_PLAIN)
        .body(body);
    let core = match html {
        Some(html) => ComposedBody::Multi(
            MultiPart::alternative()
                .singlepart(text_part)
                .singlepart(SinglePart::builder().header(ContentType::TEXT_HTML).body(html)),
        ),
        None => ComposedBody::Single(text_part),
    };
    if attachments.is_empty() {
        return core;
    }
    let mut mixed = match core {
        ComposedBody::Single(part) => MultiPart::mixed().singlepart(part),
        ComposedBody::Multi(alternative) => MultiPart::mixed().multipart(alternative),
    };
    for attachment in attachments {
        // Parte già codificata in prepare(): la dimensione misurata dal
        // budget è esattamente quella che entra nel messaggio.
        mixed = mixed.singlepart(attachment.part.clone());
    }
    ComposedBody::Multi(mixed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    const SENTINEL_UNIT_BYTES: &[u8] = b"SENTINEL-UNIT-ESTERNA";

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn tmp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("attach-unit-{}-{}", std::process::id(), tag));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    /// Escape without symlinks: `..` passed DIRECTLY to `open_regular_beneath`,
    /// bypassing `validate_relative` (which intercepts it first today). The
    /// kernel guard (RESOLVE_BENEATH) must stop it on its own: a second line
    /// of defense, not decoration.
    ///
    /// The sentinel sits EXACTLY where `..` would find it
    /// (`<parent>/outside/sentinel.txt`, not `<parent>/<root>-outside/...`)
    /// and the POSITIVE CONTROL shows that, removing only RESOLVE_BENEATH,
    /// that same sentinel becomes readable: the test measures BENEATH, not
    /// an ENOENT.
    #[test]
    fn openat2_beneath_blocks_dotdot_without_validate_relative() {
        // EXCLUSIVE base created by the test: root and outside live INSIDE
        // the same temporary tree, so '..' stays within our tree and the
        // cleanup never touches shared directories such as /tmp (a past
        // regression had root.parent() == /tmp).
        let base = tmp_root("beneath-dotdot");
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        fs::write(outside.join("sentinel.txt"), b"SENTINEL-ATTACH").expect("sentinel");
        fs::write(root.join("reale.txt"), b"reale").expect("reale");

        // Controllo positivo 1: il path legittimo apre.
        let ok = open_regular_beneath(&root, "reale.txt");
        assert!(ok.is_ok(), "path legittimo deve aprire: {:?}", ok.err());

        // CONTROLLO POSITIVO 2 (R3): senza RESOLVE_BENEATH (solo NO_SYMLINKS)
        // la STESSA fuga legge la STESSA sentinella — quindi il fallimento del
        // caso negativo è imputabile a BENEATH e non all'assenza del file.
        let mut positive = open_regular_beneath_with(
            &root,
            "../outside/sentinel.txt",
            libc::RESOLVE_NO_SYMLINKS as u64,
        )
        .expect("senza BENEATH la sentinella oltre la radice deve essere leggibile");
        let mut contents = Vec::new();
        std::io::Read::read_to_end(&mut positive, &mut contents).expect("lettura sentinella");
        assert_eq!(contents, b"SENTINEL-ATTACH", "contenuto sentinella oltre la radice");

        // Caso negativo: con i flag di produzione la fuga è bloccata.
        let result = open_regular_beneath(&root, "../outside/sentinel.txt");
        assert!(
            result.is_err(),
            "fuga con '..' deve essere bloccata dal kernel (RESOLVE_BENEATH)"
        );

        // Cleanup: SOLO l'albero creato da questo test.
        let _ = fs::remove_dir_all(&base);
    }

    /// The count of bytes read is measured by an independent METER — a test
    /// reader-wrapper counting the bytes pulled by `read_bounded` — not by
    /// the error message the code itself produces. The file is 5 MB and the
    /// budget tiny: the counter must stop near the budget, far from the end
    /// of the file.
    #[test]
    fn read_bounded_bytes_consumed_measured_by_independent_meter() {
        let dir = tmp_root("meter");
        let big = dir.join("big.bin");
        fs::write(&big, &vec![b'M'; 5_000_000]).expect("file 5MB");
        let file = fs::File::open(&big).expect("open");

        let max_raw: u64 = 64 * 1024;
        let mut pulled: u64 = 0;
        struct Meter<'a, R: Read> { inner: R, pulled: &'a mut u64 }
        impl<'a, R: Read> Read for Meter<'a, R> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.inner.read(buf)?;
                *self.pulled += n as u64;
                Ok(n)
            }
        }
        let result = read_bounded(
            Meter { inner: file, pulled: &mut pulled },
            max_raw,
            "big.bin",
        );
        assert!(result.is_err(), "budget minuscolo su file da 5MB: atteso errore");
        assert!(
            pulled <= max_raw + 65_536 + 1,
            "metro indipendente: lettura fermata vicino al budget, tirati {pulled} byte"
        );
        assert!(
            pulled * 10 < 5_000_000,
            "letti {pulled} byte su 5.000.000: la lettura NON deve arrivare in fondo"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Discriminating test on the open->read window. A barrier is PINNED
    /// between the open and the read of the REAL prepare: when it fires,
    /// `target.bin` becomes a symlink to the external sentinel. A correct
    /// implementation (fd already open) reads the benign content. A
    /// "reopen by name" mutant after the barrier pulls in the sentinel
    /// instead and fails.
    #[test]
    fn prepare_reads_from_the_already_open_fd_across_post_open_swap() {
        use std::os::unix::fs::symlink;

        let base = tmp_root("post-open-swap");
        let root = base.join("staging");
        let outside = base.join("outside");
        fs::create_dir_all(&root).expect("root");
        fs::create_dir_all(&outside).expect("outside");
        let benign_bytes = b"contenuto-benigno-del-fd-aperto";
        fs::write(root.join("target.bin"), benign_bytes).expect("benigno");
        let sentinel = outside.join("sentinel.txt");
        fs::write(&sentinel, SENTINEL_UNIT_BYTES).expect("sentinella");

        let swap_root = root.clone();
        let swap_sentinel = outside.clone();
        AFTER_OPEN_HOOK.lock().expect("lock").replace(Box::new(move || {
            let _ = fs::remove_file(swap_root.join("target.bin"));
            symlink(swap_sentinel.join("sentinel.txt"), swap_root.join("target.bin"))
                .expect("symlink post-open");
        }));

        let prepared = prepare(
            &root,
            [AttachmentInput { path: "target.bin", filename: None, mime: None }],
            AttachmentLimits { max_mime_bytes: 25_000_000, max_count: 50 },
        )
        .expect("implementazione corretta: legge dal fd GIÀ APERTO, immune allo scambio post-open");

        assert_eq!(prepared.len(), 1);
        assert_eq!(
            prepared[0].body, *benign_bytes,
            "il body deve essere quello del fd aperto PRIMA dello scambio: \
             byte della sentinella = riapertura per nome = mutante"
        );
        assert!(
            !contains(&prepared[0].body, SENTINEL_UNIT_BYTES),
            "nessun byte della sentinella nel body"
        );
        assert!(AFTER_OPEN_HOOK.lock().expect("lock").is_none());
        let _ = fs::remove_dir_all(&base);
    }

    /// An IMPLICIT basename goes through the same validation as an explicit
    /// name — the backslash is a valid filename character on Unix and must
    /// never end up in a header.
    #[test]
    fn implicit_basename_rejects_backslash() {
        assert!(exposed_name(None, "back\\slash.bin").is_err());
        assert!(exposed_name(Some("back\\slash.bin"), "qualsiasi.bin").is_err());
        // Il nome esplicito senza separatori resta valido.
        assert_eq!(
            exposed_name(Some("backslash.bin"), "qualsiasi.bin").expect("ok"),
            "backslash.bin"
        );
    }
}
