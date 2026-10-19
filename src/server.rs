use std::borrow::Cow;
use std::fs;
use std::sync::Arc;

use futures_util::TryStreamExt;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::*;
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::Deserialize;

use crate::config::EmailConfig;
use crate::error::EmailError;
use crate::folder::{self, FolderInfo};
use crate::message::{self, EmailSummary};
use crate::provider::EmailProvider;
use crate::provider::imap_provider::ImapProvider;
use crate::search_boundary;
use std::path::{Component, Path, PathBuf};

// ── Security helpers (sanitization for IMAP + filesystem sinks) ──────

/// RFC 3501 §6.4.4/§9 quoted-string escape: backslash and double-quote MUST be
/// backslash-escaped inside the quoted form. Use for EVERY user value placed
/// inside an IMAP `"..."` quoted string, to prevent SEARCH command injection.
fn escape_imap_literal(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Month abbreviations IMAP SEARCH expects in `dd-Mon-yyyy` (RFC 3501 §9).
const IMAP_MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Days per month (non-leap; February 29 accepted only on leap years).
fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 => {
            let leap =
                (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
            Some(if leap { 29 } else { 28 })
        }
        _ => None,
    }
}

/// True when a fetched-flag string marks the message as seen. The IMAP
/// layer surfaces flags through `Debug`, so we match the flag name and the
/// RFC name; the unit tests pin both renderings.
pub(crate) fn flag_is_seen(flag: &str) -> bool {
    flag == "Seen" || flag == "\\Seen"
}

/// Normalize a user-supplied date to the IMAP SEARCH form `dd-Mon-yyyy`.
///
/// Accepts ISO `YYYY-MM-DD` (the format every caller reasonably tries first)
/// and the native IMAP form
/// (`dd-Mon-yyyy`, month name case-insensitive, normalized to title case).
/// The error always names both accepted formats: a date mistake must reach
/// the caller as an MCP error, never collapse into "zero emails".
pub(crate) fn normalize_imap_date(s: &str) -> Result<String, McpError> {
    let trimmed = s.trim();
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
    {
        let year: u32 = parts[0].parse().map_err(|_| date_error(trimmed))?;
        let month: u32 = parts[1].parse().map_err(|_| date_error(trimmed))?;
        let day: u32 = parts[2].parse().map_err(|_| date_error(trimmed))?;
        return imap_date_from(year, month, day, trimmed);
    }
    if parts.len() == 3
        && (1..=2).contains(&parts[0].len())
        && parts[0].chars().all(|c| c.is_ascii_digit())
        && parts[1].len() == 3
        && parts[1].chars().all(|c| c.is_ascii_alphabetic())
        && parts[2].len() == 4
        && parts[2].chars().all(|c| c.is_ascii_digit())
    {
        let day: u32 = parts[0].parse().map_err(|_| date_error(trimmed))?;
        let month_name = parts[1];
        let month = 1 + IMAP_MONTHS
            .iter()
            .position(|m| m.eq_ignore_ascii_case(month_name))
            .ok_or_else(|| date_error(trimmed))? as u32;
        let year: u32 = parts[2].parse().map_err(|_| date_error(trimmed))?;
        return imap_date_from(year, month, day, trimmed);
    }
    Err(date_error(trimmed))
}

fn imap_date_from(year: u32, month: u32, day: u32, original: &str) -> Result<String, McpError> {
    let max_day = days_in_month(year, month).ok_or_else(|| date_error(original))?;
    if day == 0 || day > max_day {
        return Err(date_error(original));
    }
    Ok(format!(
        "{day:02}-{}-{year}",
        IMAP_MONTHS[(month - 1) as usize]
    ))
}

fn date_error(original: &str) -> McpError {
    McpError::invalid_params(
        format!(
            "Invalid date '{original}': expected ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy' (e.g. 30-Aug-2026)"
        ),
        None,
    )
}

/// Validate an IMAP sequence-set (UID range): digits, `,`, `:`, `*` only.
fn validate_sequence_set(s: &str) -> Result<&str, McpError> {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || matches!(c, ',' | ':' | '*'))
    {
        Ok(s)
    } else {
        Err(McpError::internal_error(
            format!("Invalid UID sequence set: {s}"),
            None,
        ))
    }
}

/// Validate an RFC 5322 header field-name used UNQUOTED in IMAP `HEADER` and
/// `BODY[HEADER.FIELDS (...)]`: letters, digits and `-` only. Rejects spaces,
/// parentheses, quotes and any token that could inject extra SEARCH/FETCH keys.
fn validate_header_name(s: &str) -> Result<&str, McpError> {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        Ok(s)
    } else {
        Err(McpError::internal_error(
            format!("Invalid header field name: {s}"),
            None,
        ))
    }
}

/// Compose ONE Gmail search-language term for the X-GM-RAW extension.
///
/// The Gmail search language treats a QUOTED value as an exact-phrase
/// match, so `from:"alpine"` returns ZERO hits against a message from
/// alpine-lodge@example.com while the bare token `from:alpine` matches.
/// Quoting every value — the old behavior — silently broke every string
/// search routed through X-GM-RAW.
///
/// The quotes are not decoration, though: a value with spaces or syntax
/// characters still needs the quoted form to be searchable, and an
/// unquoted value must never smuggle extra search keys into the query.
/// So:
/// - a bare token (alphanumerics plus the address-safe set `._%+-@`, the
///   shape of usernames and domains) is emitted UNQUOTED: word match;
/// - anything else is emitted as a quoted phrase: exact-phrase match;
/// - a value that contains a double quote cannot be expressed reliably
///   inside a Gmail quoted phrase, and an empty value matches nothing
///   meaningful: both are REFUSED with an explicit error — a visible
///   failure, never an ambiguous query nor a silent empty result;
/// - backslashes are left RAW here: the Gmail language reads them as
///   literals, and the IMAP-level escaping of the whole X-GM-RAW argument
///   happens once at the composition site (`escape_imap_literal(&raw)`).
fn gmail_search_term(key: Option<&str>, value: &str) -> Result<String, McpError> {
    let bare_token = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@'));
    if bare_token {
        return Ok(match key {
            Some(k) => format!("{k}:{value}"),
            None => value.to_string(),
        });
    }
    if value.trim().is_empty() {
        return Err(McpError::internal_error(
            format!(
                "Gmail search: empty value for {} matches nothing — refusing",
                key.unwrap_or("term")
            ),
            None,
        ));
    }
    if value.contains('"') {
        return Err(McpError::internal_error(
            format!(
                "Gmail search: double quotes inside the {} value are not expressible in a quoted phrase — refusing",
                key.unwrap_or("term")
            ),
            None,
        ));
    }
    Ok(match key {
        Some(k) => format!("{k}:\"{value}\""),
        None => format!("\"{value}\""),
    })
}

/// Confine an attachment `save_path` to `base`: reject absolute paths and `..`
/// traversal so a manipulated agent cannot overwrite arbitrary files.
fn resolve_save_path(base: &Path, requested: &str) -> Result<PathBuf, McpError> {
    let req = Path::new(requested);
    for comp in req.components() {
        if matches!(
            comp,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(McpError::internal_error(
                "save_path must be a relative path within the download directory \
                 (absolute paths and '..' are rejected)"
                    .to_string(),
                None,
            ));
        }
    }
    Ok(base.join(req))
}

/// Base directory attachments may be written to (`EMAIL_DOWNLOAD_DIR`, else cwd).
fn download_base_dir() -> PathBuf {
    std::env::var_os("EMAIL_DOWNLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
}

/// Outcome of removing messages marked \Deleted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpungeOutcome {
    /// UIDPLUS: UID EXPUNGE mirato sui soli uid richiesti.
    Targeted,
    /// Without UIDPLUS: NO expunge. A global EXPUNGE removes every message
    /// marked \Deleted, and a prior snapshot of the state does not close the
    /// window in which another client marks others. The requested messages
    /// stay marked and the response states the deferral.
    DeferredMarkedOnly,
}

// Esito di un APPEND di draft: `new_uid` e' Some solo quando il server ha
// restituito l'APPENDUID response code (RFC 4315, UIDPLUS).
struct DraftAppendOutcome {
    new_uid: Option<u32>,
}

/// Manual APPEND of a message into the draft folder.
///
/// Why NOT `Session::append`: it consumes the tagged response and loses the
/// `[APPENDUID uidvalidity uid]` response code, and it cannot tell a definite
/// failure from an UNCERTAIN outcome. Here:
/// - failure BEFORE the literal is sent (server answers NO/BAD to the APPEND
///   command, or the connection drops at once): a definite error, the old
///   draft is intact by construction because no destructive step has
///   happened yet;
/// - failure AFTER the literal is sent (connection dropped or peer silent
///   waiting for the tagged OK): an explicitly declared UNCERTAIN outcome —
///   the server MAY have stored the message; the caller must not retry
///   blindly;
/// - success: parse APPENDUID to return the new UID.
///
/// The receiver is a real state machine: the server may send untagged data
/// before the continuation (RFC 3501 §2.2.1) and it is consumed without
/// concluding a false rejection; every read has an operational timeout: a
/// connected but silent peer yields the uncertain outcome, not an infinite
/// wait. A session left mid-command must be DISCARDED by the caller (which is
/// why the append runs on a dedicated connection, see update_draft).
async fn append_new_draft(
    session: &mut crate::pool::TlsImapSession,
    mailbox: &str,
    raw: &[u8],
    operation_timeout: std::time::Duration,
) -> Result<DraftAppendOutcome, McpError> {
    use async_imap::imap_proto::types::{Response, ResponseCode, Status};

    // The limit is an OVERALL DEADLINE on the operation (from the APPEND
    // command to the final response), not a timeout that rearms on every
    // read: a server sending untagged traffic forever cannot keep the
    // connection open indefinitely.
    let deadline = tokio::time::Instant::now() + operation_timeout;
    let remaining = || deadline.saturating_duration_since(tokio::time::Instant::now());

    // Quoting RFC 3501 della mailbox (l'helper `validate_str` della crate
    // non e' pubblico): backslash e doppi apici escaped dentro "...".
    let mailbox_quoted = format!("\"{}\"", mailbox.replace('\\', "\\\\").replace('"', "\\\""));
    let id = tokio::time::timeout(
        remaining(),
        session.run_command(format!("APPEND {} {{{}}}", mailbox_quoted, raw.len())),
    )
    .await
    .map_err(|_| {
        McpError::internal_error(
            "draft APPEND abandoned: the operation deadline expired BEFORE the literal was sent; the message was NOT transferred and the old draft is intact; the connection was discarded",
            None,
        )
    })?
    .map_err(|e| {
        McpError::internal_error(
            format!("draft APPEND command failed before any destructive step (old draft intact): {e}"),
            None,
        )
    })?;
    let id_text = id.0.clone();

    // Phase 1 — waiting for the continuation. The server may legitimately
    // send untagged responses before the continuation: they are consumed and
    // the loop continues up to the continuation (proceed) or a tagged
    // response for our tag (definite rejection).
    loop {
        match tokio::time::timeout(remaining(), session.read_response()).await {
            Err(_elapsed) => {
                return Err(McpError::internal_error(
                    "draft APPEND abandoned: the operation deadline expired BEFORE the literal was sent (untagged traffic or silence kept the APPEND open); the message was NOT transferred and the old draft is intact; the connection was discarded",
                    None,
                ));
            }
            Ok(Err(e)) => {
                return Err(McpError::internal_error(
                    format!(
                        "draft APPEND failed before the literal was sent (old draft intact, definite failure): {e}"
                    ),
                    None,
                ));
            }
            Ok(Ok(None)) => {
                return Err(McpError::internal_error(
                    "draft APPEND failed before the literal was sent (old draft intact, definite failure): connection closed",
                    None,
                ));
            }
            Ok(Ok(Some(res))) => match res.parsed() {
                Response::Continue { .. } => break,
                Response::Done {
                    tag,
                    status,
                    information,
                    ..
                } if tag.0 == id_text => {
                    let information = information.as_deref().unwrap_or("");
                    return Err(McpError::internal_error(
                        format!(
                            "draft APPEND rejected by the server before the literal was sent (old draft intact, definite failure): {status:?} {information}"
                        ),
                        None,
                    ));
                }
                _ => continue, // untagged prima della continuation: consuma e prosegui
            },
        }
    }

    // The literal was accepted: from here an I/O error no longer defines the
    // append as failed, but as an UNCERTAIN outcome. The WRITE is also inside
    // the overall deadline — a blocked write (a peer that does not read)
    // cannot stay suspended without a limit.
    {
        use tokio::io::AsyncWriteExt;
        let stream = session.as_mut();
        write_with_deadline(stream, raw, remaining()).await?;
        write_with_deadline(stream, b"\r\n", remaining()).await?;
        let remaining = remaining();
        match tokio::time::timeout(remaining, stream.flush()).await {
            Err(_) => {
                return Err(append_uncertain(
                    "literal flush timed out: part of the message may have been transferred"
                        .to_string(),
                ));
            }
            Ok(Err(e)) => return Err(append_uncertain(e.to_string())),
            Ok(Ok(())) => {}
        }
    }

    loop {
        let res = match tokio::time::timeout(remaining(), session.read_response()).await {
            Err(_elapsed) => {
                return Err(append_uncertain(
                    "the operation deadline expired while waiting for the APPEND result (silence or unbounded untagged traffic): the message literal WAS transferred, so the server may or may not have stored it"
                        .to_string(),
                ));
            }
            Ok(Err(e)) => return Err(append_uncertain(e.to_string())),
            Ok(Ok(None)) => {
                return Err(append_uncertain(
                    "connection closed while waiting for the APPEND result".to_string(),
                ));
            }
            Ok(Ok(Some(res))) => res,
        };
        let Response::Done {
            tag,
            status,
            code,
            information,
        } = res.parsed()
        else {
            // Risposte untagged (EXISTS, FETCH, ...) durante l'append: ignora.
            continue;
        };
        if tag.0 != id_text {
            continue;
        }
        let information = information.as_deref().unwrap_or("");
        if *status != Status::Ok {
            return Err(McpError::internal_error(
                format!(
                    "draft APPEND rejected by the server after the literal was sent (old draft intact, definite failure): {information}"
                ),
                None,
            ));
        }
        let new_uid = match code.as_ref() {
            Some(ResponseCode::AppendUid(_uidvalidity, uids)) => {
                // L'ultimo elemento dell'uid-set e' l'uid del messaggio appena
                // appeso; gli intervalli si riducono al loro estremo superiore.
                uids.iter().next_back().map(|m| match m {
                    async_imap::imap_proto::types::UidSetMember::Uid(u) => *u,
                    async_imap::imap_proto::types::UidSetMember::UidRange(r) => *r.end(),
                })
            }
            _ => None,
        };
        return Ok(DraftAppendOutcome { new_uid });
    }
}

/// Write of a literal chunk within the overall deadline: a blocked write (a
/// peer that does not read) must produce the uncertain outcome within the
/// limit, not stay suspended forever.
async fn write_with_deadline(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    chunk: &[u8],
    remaining: std::time::Duration,
) -> Result<(), McpError> {
    use tokio::io::AsyncWriteExt;
    match tokio::time::timeout(remaining, stream.write_all(chunk)).await {
        Err(_) => Err(append_uncertain(
            "literal write timed out: part of the message may have been transferred".to_string(),
        )),
        Ok(Err(e)) => Err(append_uncertain(e.to_string())),
        Ok(Ok(())) => Ok(()),
    }
}

fn append_uncertain(detail: String) -> McpError {
    McpError::internal_error(
        format!(
            "draft APPEND outcome UNCERTAIN: the message literal was already sent but the final result was not received ({detail}). The old draft was left intact and NO retry was attempted: verify on the server whether the new draft arrived before repeating the operation"
        ),
        None,
    )
}

// ── Tool parameter types ────────────────────────────────────────

macro_rules! impl_schema {
    ($ty:ty, $name:literal, $schema:tt) => {
        impl JsonSchema for $ty {
            fn schema_name() -> Cow<'static, str> {
                Cow::Borrowed($name)
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                schemars::json_schema!($schema)
            }
        }
    };
}

#[derive(Debug, Deserialize)]
pub struct ListEmailsParams {
    pub folder: Option<String>,
    pub limit: Option<u32>,
    pub unseen_only: Option<bool>,
    pub since_date: Option<String>,
}

impl_schema!(ListEmailsParams, "ListEmailsParams", {
    "type": "object",
    "properties": {
        "folder": { "type": "string" },
        "limit": { "type": "integer", "minimum": 1 },
        "unseen_only": { "type": "boolean", "description": "Only messages without the \\Seen flag (server-searched and re-filtered on fetched flags)" },
        "since_date": { "type": "string", "description": "Date filter, ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy' (e.g. 30-Aug-2026)" }
    },
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct ListRecentUnseenParams {
    pub folder: Option<String>,
    pub limit: Option<u32>,
    pub since_date: Option<String>,
}

impl_schema!(ListRecentUnseenParams, "ListRecentUnseenParams", {
    "type": "object",
    "properties": {
        "folder": { "type": "string", "description": "Folder to scan (default INBOX); use the name returned by list_folders" },
        "limit": { "type": "integer", "minimum": 1 },
        "since_date": { "type": "string", "description": "Date filter, ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy' (e.g. 30-Aug-2026)" }
    },
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct GetEmailParams {
    pub uid: u32,
    pub folder: Option<String>,
}

impl_schema!(GetEmailParams, "GetEmailParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" }
    },
    "required": ["uid"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct SearchEmailsParams {
    pub folder: Option<String>,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub body: Option<String>,
    pub to: Option<String>,
    pub cc: Option<String>,
    pub before: Option<String>,
    pub since: Option<String>,
    pub header: Option<String>,
    pub uid_range: Option<String>,
    pub limit: Option<u32>,
}

impl_schema!(SearchEmailsParams, "SearchEmailsParams", {
    "type": "object",
    "properties": {
        "folder": { "type": "string" },
        "subject": { "type": "string" },
        "from": { "type": "string" },
        "body": { "type": "string" },
        "to": { "type": "string" },
        "cc": { "type": "string" },
        "before": { "type": "string", "description": "Date filter, ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy'" },
        "since": { "type": "string", "description": "Date filter, ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy'" },
        "header": { "type": "string" },
        "uid_range": { "type": "string" },
        "limit": { "type": "integer", "minimum": 1 }
    },
    "additionalProperties": false
});

/// One file to attach, read by the SERVER from `EMAIL_ATTACH_DIR`. Never base64:
/// the server reads the local file, the model never carries bytes.
///
/// - `path`: RELATIVE path under `EMAIL_ATTACH_DIR`. Absolute paths, `..` and
///   symlinks (including intermediate ones) are rejected; opening is atomic via
///   `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` and only regular files are
///   accepted.
/// - `filename`: name exposed in the email. Default: basename of `path`.
///   Rejected: empty, `.`, `..`, path separators, CR/LF.
/// - `mime`: explicit `type/subtype` (RFC token, no parameters). Default:
///   case-insensitive extension map (pdf, jpg, jpeg, png, docx, txt) with
///   fallback `application/octet-stream`.
#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(inline)]
pub struct AttachmentParam {
    /// Relative path under `EMAIL_ATTACH_DIR` (absolute paths, `..` and symlinks rejected).
    pub path: String,
    /// Name exposed in the email; defaults to the basename of `path`. Path separators and CR/LF rejected.
    pub filename: Option<String>,
    /// Explicit MIME `type/subtype`; defaults from the extension map, fallback `application/octet-stream`.
    pub mime: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendEmailParams {
    /// Primary recipients: a single address or a comma/semicolon separated
    /// list (`a@x.test, b@x.test`); quoted display names are supported
    /// (`"Doe, John" <a@x.test>`). RFC 5322 groups and comments are rejected.
    pub to: String,
    pub subject: String,
    pub body: Option<String>,
    pub html: Option<String>,
    /// Carbon-copy recipients: same list syntax as `to`; omit or `null`
    /// for none.
    pub cc: Option<String>,
    /// Blind carbon-copy recipients: same list syntax as `to`. They are
    /// NEVER written in the message headers: they receive the message via
    /// the SMTP envelope only (RFC 5322 §3.6.3). Omit or `null` for none.
    pub bcc: Option<String>,
    pub reply_to: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    /// Override sender address. Must match one of `smtp.allowed_from` when configured.
    pub from: Option<String>,
    /// Files to attach, read by the server from `EMAIL_ATTACH_DIR` (relative
    /// paths; never base64). When `EMAIL_ATTACH_DIR` is not configured, any
    /// request carrying attachments is rejected with an explicit error.
    pub attachments: Option<Vec<AttachmentParam>>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteEmailParams {
    pub uid: u32,
    pub folder: Option<String>,
}

impl_schema!(DeleteEmailParams, "DeleteEmailParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" }
    },
    "required": ["uid"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct MoveEmailParams {
    pub uid: u32,
    pub from_folder: Option<String>,
    pub to_folder: String,
}

impl_schema!(MoveEmailParams, "MoveEmailParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "from_folder": { "type": "string" },
        "to_folder": { "type": "string" }
    },
    "required": ["uid", "to_folder"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct FlagEmailParams {
    pub uid: u32,
    pub folder: Option<String>,
    pub flagged: bool,
}

impl_schema!(FlagEmailParams, "FlagEmailParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" },
        "flagged": { "type": "boolean" }
    },
    "required": ["uid", "flagged"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct MarkSeenParams {
    pub uid: u32,
    pub folder: Option<String>,
    pub seen: bool,
}

impl_schema!(MarkSeenParams, "MarkSeenParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" },
        "seen": { "type": "boolean" }
    },
    "required": ["uid", "seen"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize, JsonSchema)]
pub struct MoveThreadParams {
    pub subject: String,
    pub from_folder: String,
    pub to_folder: String,
    pub from_address: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ListDraftsParams {
    pub limit: Option<u32>,
}

impl_schema!(ListDraftsParams, "ListDraftsParams", {
    "type": "object",
    "properties": {
        "limit": { "type": "integer", "minimum": 1 }
    },
    "additionalProperties": false
});

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateDraftParams {
    /// Primary recipients: a single address or a comma/semicolon separated
    /// list; quoted display names are supported. RFC 5322 groups and
    /// comments are rejected.
    pub to: String,
    pub subject: String,
    pub body: Option<String>,
    pub html: Option<String>,
    /// Carbon-copy recipients: same list syntax as `to`; omit or `null`
    /// for none.
    pub cc: Option<String>,
    /// Blind carbon-copy recipients: same list syntax as `to`. The private
    /// IMAP draft KEEPS the Bcc header (so the draft stays editable);
    /// the Bcc header is stripped when the message is sent.
    pub bcc: Option<String>,
    /// Files to attach, read by the server from `EMAIL_ATTACH_DIR` (relative
    /// paths; never base64). When `EMAIL_ATTACH_DIR` is not configured, any
    /// request carrying attachments is rejected with an explicit error.
    pub attachments: Option<Vec<AttachmentParam>>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDraftParams {
    pub uid: u32,
    pub to: String,
    pub subject: String,
    pub body: Option<String>,
    pub html: Option<String>,
    pub cc: Option<String>,
    pub bcc: Option<String>,
    /// Files to attach, read by the server from `EMAIL_ATTACH_DIR` (relative
    /// paths; never base64). NO implicit preservation: omitting `attachments`
    /// or passing `[]` produces a draft WITHOUT attachments; re-attach
    /// explicitly what you want to keep.
    pub attachments: Option<Vec<AttachmentParam>>,
}

impl_schema!(UpdateDraftParams, "UpdateDraftParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "to": { "type": "string", "description": "Primary recipients: a single address or a comma/semicolon separated list; quoted display names are supported. RFC 5322 groups and comments are rejected." },
        "subject": { "type": "string" },
        "body": { "type": "string" },
        "html": { "type": "string" },
        "cc": { "type": "string", "description": "Carbon-copy recipients: same list syntax as `to`. FULL REPLACEMENT: omitting cc removes the Cc header from the new draft." },
        "bcc": { "type": "string", "description": "Blind carbon-copy recipients: same list syntax as `to`; the private draft keeps the Bcc header (stripped when sending). FULL REPLACEMENT: omitting bcc removes the Bcc header from the new draft." },
        "attachments": {
            "type": "array",
            "description": "Files to attach, read by the server from EMAIL_ATTACH_DIR (relative paths; never base64). NO implicit preservation: omitting attachments or passing [] produces a draft WITHOUT attachments; re-attach explicitly what you want to keep.",
            "items": {
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Relative path under EMAIL_ATTACH_DIR (absolute paths, .. and symlinks rejected)." },
                    "filename": { "type": "string", "description": "Name exposed in the email; defaults to the basename of path. Path separators and CR/LF rejected." },
                    "mime": { "type": "string", "description": "Explicit MIME type/subtype; defaults from the extension map, fallback application/octet-stream." }
                },
                "required": ["path"],
                "additionalProperties": false
            }
        }
    },
    "required": ["uid", "to", "subject"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct DownloadAttachmentParams {
    pub uid: u32,
    pub part_id: String,
    pub folder: Option<String>,
    pub save_path: Option<String>,
}

impl_schema!(DownloadAttachmentParams, "DownloadAttachmentParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "part_id": { "type": "string" },
        "folder": { "type": "string" },
        "save_path": { "type": "string" }
    },
    "required": ["uid", "part_id"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFolderParams {
    pub folder: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteFolderParams {
    pub folder: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RenameFolderParams {
    pub old_name: String,
    pub new_name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct GetQuotaParams {
    pub root: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IdleWaitParams {
    pub folder: Option<String>,
    pub timeout_secs: Option<u64>,
}

impl_schema!(IdleWaitParams, "IdleWaitParams", {
    "type": "object",
    "properties": {
        "folder": { "type": "string" },
        "timeout_secs": { "type": "integer", "minimum": 1 }
    },
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct CopyEmailParams {
    pub uid: u32,
    pub from_folder: Option<String>,
    pub to_folder: String,
}

impl_schema!(CopyEmailParams, "CopyEmailParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "from_folder": { "type": "string" },
        "to_folder": { "type": "string" }
    },
    "required": ["uid", "to_folder"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct GetBodystructureParams {
    pub uid: u32,
    pub folder: Option<String>,
}

impl_schema!(GetBodystructureParams, "GetBodystructureParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" }
    },
    "required": ["uid"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct GetEmailRawParams {
    pub uid: u32,
    pub folder: Option<String>,
}

impl_schema!(GetEmailRawParams, "GetEmailRawParams", {
    "type": "object",
    "properties": {
        "uid": { "type": "integer", "minimum": 1 },
        "folder": { "type": "string" }
    },
    "required": ["uid"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct BatchMarkSeenParams {
    pub uids: Vec<u32>,
    pub folder: Option<String>,
    pub seen: bool,
}

impl_schema!(BatchMarkSeenParams, "BatchMarkSeenParams", {
    "type": "object",
    "properties": {
        "uids": {
            "type": "array",
            "items": { "type": "integer", "minimum": 1 }
        },
        "folder": { "type": "string" },
        "seen": { "type": "boolean" }
    },
    "required": ["uids", "seen"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct BatchDeleteParams {
    pub uids: Vec<u32>,
    pub folder: Option<String>,
}

impl_schema!(BatchDeleteParams, "BatchDeleteParams", {
    "type": "object",
    "properties": {
        "uids": {
            "type": "array",
            "items": { "type": "integer", "minimum": 1 }
        },
        "folder": { "type": "string" }
    },
    "required": ["uids"],
    "additionalProperties": false
});

#[derive(Debug, Deserialize)]
pub struct ListEmailsWithHeadersParams {
    pub folder: Option<String>,
    pub headers: Vec<String>,
    pub limit: Option<u32>,
    pub unseen_only: Option<bool>,
    pub since_date: Option<String>,
}

impl_schema!(ListEmailsWithHeadersParams, "ListEmailsWithHeadersParams", {
    "type": "object",
    "properties": {
        "folder": { "type": "string" },
        "headers": {
            "type": "array",
            "items": { "type": "string" }
        },
        "limit": { "type": "integer", "minimum": 1 },
        "unseen_only": { "type": "boolean", "description": "Only messages without the \\Seen flag (server-searched and re-filtered on fetched flags)" },
        "since_date": { "type": "string", "description": "Date filter, ISO 'YYYY-MM-DD' (e.g. 2026-08-30) or IMAP 'dd-Mon-yyyy' (e.g. 30-Aug-2026)" }
    },
    "required": ["headers"],
    "additionalProperties": false
});

// ── Server ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct EmailServer {
    provider: Arc<dyn EmailProvider>,
    tool_router: ToolRouter<Self>,
    smtp_transport: Arc<tokio::sync::OnceCell<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>>>,
    config: EmailConfig,
}

#[tool_router]
impl EmailServer {
    pub fn from_config(config: EmailConfig) -> Result<Self, EmailError> {
        let provider = ImapProvider::new(&config)?;
        Ok(Self {
            provider: Arc::new(provider),
            tool_router: Self::tool_router(),
            smtp_transport: Arc::new(tokio::sync::OnceCell::new()),
            config,
        })
    }

    /// Reject explicit `from` overrides that are not authorized by the
    /// resolved allowlist. The default-from is always allowed implicitly so
    /// existing callers without `from` keep working.
    fn validate_from_override(
        requested: Option<&str>,
        default_from: &str,
        allowed: &[String],
    ) -> Result<(), McpError> {
        match requested {
            None => Ok(()),
            Some(addr) if addr == default_from => Ok(()),
            Some(addr) if allowed.iter().any(|a| a == addr) => Ok(()),
            Some(addr) => Err(McpError::invalid_params(
                format!(
                    "from address '{addr}' not in smtp.allowed_from; \
                     configure it explicitly to authorize sending from this address"
                ),
                None,
            )),
        }
    }

    /// Resolve a display-form folder name (e.g. "Doc.Contabilità.VIVIenergia")
    /// to the actual IMAP folder name by querying the server and matching.
    /// Handles delimiter normalization (`.` → `/`) and UTF-7 encoding.
    async fn resolve_folder(&self, display_name: &str) -> Result<String, McpError> {
        let mut conn = self.get_imap_connection().await?;
        let folders = conn
            .list(Some(""), Some("*"))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let folders_vec: Vec<_> = folders
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        for name in &folders_vec {
            let imap_delim = name
                .delimiter()
                .and_then(|d| d.chars().next())
                .unwrap_or('/');
            let decoded = folder::decode_folder_from_imap(name.name(), imap_delim);
            // Case-insensitive match on display name
            if decoded.eq_ignore_ascii_case(display_name) {
                return Ok(name.name().to_string());
            }
        }

        // If no match, return the display name with normalized delimiter
        // (try `/` as it's the most common for Gmail)
        let normalized = display_name.replace('.', "/");
        Ok(normalized)
    }

    // ── Folder tools ────────────────────────────────────────────

    #[tool(
        description = "List all email folders/mailboxes in the account",
        annotations(read_only_hint = true)
    )]
    async fn list_folders(&self) -> Result<CallToolResult, McpError> {
        let mut conn = self.get_imap_connection().await?;

        let folders = conn
            .list(Some(""), Some("*"))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let folders_vec: Vec<_> = folders
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Decode IMAP modified UTF-7 names to display form
        let folder_list: Vec<FolderInfo> = folders_vec
            .into_iter()
            .map(|name| {
                let delim = name
                    .delimiter()
                    .and_then(|d| d.chars().next())
                    .unwrap_or('/');
                let decoded = folder::decode_folder_from_imap(name.name(), delim);
                FolderInfo {
                    name: decoded,
                    delimiter: delim.to_string(),
                    flags: name.attributes().iter().map(|f| format!("{f:?}")).collect(),
                }
            })
            .collect();

        Ok(CallToolResult::success(vec![
            Content::json(&folder_list)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(description = "Create a new mailbox folder")]
    async fn create_folder(
        &self,
        params: Parameters<CreateFolderParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut conn = self.get_imap_connection().await?;

        conn.create(&params.folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Folder '{}' created",
            params.folder
        ))]))
    }

    #[tool(description = "Delete a mailbox folder")]
    async fn delete_folder(
        &self,
        params: Parameters<DeleteFolderParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut conn = self.get_imap_connection().await?;

        conn.delete(&params.folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Folder '{}' deleted",
            params.folder
        ))]))
    }

    #[tool(description = "Rename a mailbox folder")]
    async fn rename_folder(
        &self,
        params: Parameters<RenameFolderParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let mut conn = self.get_imap_connection().await?;

        conn.rename(&params.old_name, &params.new_name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Folder '{}' renamed to '{}'",
            params.old_name, params.new_name
        ))]))
    }

    #[tool(
        description = "Get quota information for the account",
        annotations(read_only_hint = true)
    )]
    async fn get_quota(
        &self,
        params: Parameters<GetQuotaParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let root = params.root.as_deref().unwrap_or("");
        let mut conn = self.get_imap_connection().await?;

        let quota = conn
            .get_quota(root)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let resources: Vec<serde_json::Value> = quota
            .resources
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": format!("{:?}", r.name),
                    "usage": r.usage,
                    "limit": r.limit,
                })
            })
            .collect();

        Ok(CallToolResult::success(vec![
            Content::json(serde_json::json!({
                "root": quota.root_name,
                "resources": resources,
            }))
            .map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(
        description = "List IMAP namespaces available on the server",
        annotations(read_only_hint = true)
    )]
    async fn list_namespaces(&self) -> Result<CallToolResult, McpError> {
        // async-imap 0.11 does not expose a namespace() method directly.
        // We return folder delimiter info from LIST instead.
        let mut conn = self.get_imap_connection().await?;

        let folders = conn
            .list(Some(""), Some("*"))
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let folders_vec: Vec<_> = folders
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Extract unique delimiters from folder listing
        let delimiters: std::collections::HashSet<Option<String>> = folders_vec
            .iter()
            .map(|f| f.delimiter().map(|d| d.to_string()))
            .collect();

        let result = serde_json::json!({
            "delimiters": delimiters.iter().collect::<Vec<_>>(),
            "folder_count": folders_vec.len(),
        });

        Ok(CallToolResult::success(vec![
            Content::json(&result).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    // ── Email listing and retrieval ──────────────────────────────

    #[tool(
        description = "List emails from a folder with optional filtering",
        annotations(read_only_hint = true)
    )]
    async fn list_emails(
        &self,
        params: Parameters<ListEmailsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let limit = params.limit.unwrap_or(20);

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut search_criteria = String::new();
        if params.unseen_only.unwrap_or(false) {
            search_criteria.push_str("UNSEEN ");
        }
        if let Some(ref date) = params.since_date {
            search_criteria.push_str(&format!("SINCE {} ", normalize_imap_date(date)?));
        }
        if search_criteria.is_empty() {
            search_criteria = "ALL".to_string();
        }

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, &search_criteria, self.imap_operation_timeout())
                .await?;

        let mut uid_list: Vec<u32> = uids.into_iter().collect();
        uid_list.sort_by(|a, b| b.cmp(a)); // newest first
        uid_list.truncate(limit as usize);

        if uid_list.is_empty() {
            return Ok(CallToolResult::success(vec![
                Content::json(Vec::<EmailSummary>::new())
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ]));
        }

        let uid_set = uid_list
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetches = conn
            .uid_fetch(&uid_set, "(ENVELOPE FLAGS RFC822.SIZE)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut emails: Vec<EmailSummary> = fetches_vec
            .into_iter()
            .filter_map(|f| f.uid.map(|uid| message::extract_summary(uid, &f)))
            .collect();
        if params.unseen_only.unwrap_or(false) {
            // Belt-and-braces: a SEARCH UNSEEN that lies must not surface
            // already-seen rows.
            emails.retain(|e| !e.flags.iter().any(|f| flag_is_seen(f)));
        }

        Ok(CallToolResult::success(vec![
            Content::json(&emails).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(
        description = "Read-only tick primitive: the newest unseen messages of a folder in one stable shape (items + uids + count). Accepts since_date in ISO YYYY-MM-DD or IMAP dd-Mon-yyyy. Errors surface as MCP errors, never as an empty list.",
        annotations(read_only_hint = true)
    )]
    async fn list_recent_unseen(
        &self,
        params: Parameters<ListRecentUnseenParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let limit = params.limit.unwrap_or(20);

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut search_criteria = String::from("UNSEEN ");
        if let Some(ref date) = params.since_date {
            search_criteria.push_str(&format!("SINCE {} ", normalize_imap_date(date)?));
        }

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, &search_criteria, self.imap_operation_timeout())
                .await?;

        let mut uid_list: Vec<u32> = uids.into_iter().collect();
        uid_list.sort_by(|a, b| b.cmp(a)); // newest first
        uid_list.truncate(limit as usize);

        let mut items: Vec<EmailSummary> = Vec::new();
        if !uid_list.is_empty() {
            let uid_set = uid_list
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let fetches = conn
                .uid_fetch(&uid_set, "(ENVELOPE FLAGS RFC822.SIZE)")
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            let fetches_vec: Vec<_> = fetches
                .try_collect()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            items = fetches_vec
                .into_iter()
                .filter_map(|f| f.uid.map(|uid| message::extract_summary(uid, &f)))
                .filter(|e| !e.flags.iter().any(|f| flag_is_seen(f)))
                .collect();
        }

        let payload = serde_json::json!({
            "folder": resolved_folder,
            "count": items.len(),
            "uids": items.iter().map(|e| e.uid).collect::<Vec<_>>(),
            "items": items,
            "error": serde_json::Value::Null,
        });
        Ok(CallToolResult::success(vec![
            Content::json(&payload).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(
        description = "Get full email content by UID",
        annotations(read_only_hint = true)
    )]
    async fn get_email(
        &self,
        params: Parameters<GetEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        use crate::message::{EmailDetail, parse_email};

        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches = conn
            .uid_fetch(&params.uid.to_string(), "(BODY.PEEK[] FLAGS)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetch = fetches_vec
            .iter()
            .find(|f| f.uid == Some(params.uid))
            .ok_or_else(|| {
                McpError::internal_error(format!("Email not found: uid={}", params.uid), None)
            })?;

        let raw = fetch
            .body()
            .ok_or_else(|| McpError::internal_error("No email body in response", None))?;

        let flags: Vec<String> = fetch.flags().map(|f| format!("{f:?}")).collect();
        let detail: EmailDetail = parse_email(params.uid, raw, flags)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![
            Content::json(&detail).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(
        description = "Get the raw RFC822 source of an email (for archival)",
        annotations(read_only_hint = true)
    )]
    async fn get_email_raw(
        &self,
        params: Parameters<GetEmailRawParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches = conn
            .uid_fetch(&params.uid.to_string(), "(BODY.PEEK[])")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetch = fetches_vec
            .iter()
            .find(|f| f.uid == Some(params.uid))
            .ok_or_else(|| {
                McpError::internal_error(format!("Email not found: uid={}", params.uid), None)
            })?;

        let raw = fetch
            .body()
            .ok_or_else(|| McpError::internal_error("No email body in response", None))?;

        Ok(CallToolResult::success(vec![Content::text(
            String::from_utf8_lossy(raw).into_owned(),
        )]))
    }

    #[tool(
        description = "Get structured attachment info for an email (via RFC822 parse)",
        annotations(read_only_hint = true)
    )]
    async fn get_bodystructure(
        &self,
        params: Parameters<GetBodystructureParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches = conn
            .uid_fetch(&params.uid.to_string(), "(BODY.PEEK[])")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetch = fetches_vec
            .iter()
            .find(|f| f.uid == Some(params.uid))
            .ok_or_else(|| {
                McpError::internal_error(format!("Email not found: uid={}", params.uid), None)
            })?;

        let raw = fetch
            .body()
            .ok_or_else(|| McpError::internal_error("No email body in response", None))?;

        // Reuse parse_email for structured attachment info
        let detail = message::parse_email(params.uid, raw, vec![])
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let result = serde_json::json!({
            "uid": params.uid,
            "has_text_body": detail.text_body.is_some(),
            "has_html_body": detail.html_body.is_some(),
            "attachment_count": detail.attachments.len(),
            "attachments": detail.attachments,
        });

        Ok(CallToolResult::success(vec![
            Content::json(&result).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    // ── Search ──────────────────────────────────────────────────

    #[tool(
        description = "Search emails with advanced IMAP criteria",
        annotations(read_only_hint = true)
    )]
    async fn search_emails(
        &self,
        params: Parameters<SearchEmailsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let limit = params.limit.unwrap_or(20);

        // Gmail IMAP returns an empty set for SUBJECT/FROM/BODY/TO/CC string
        // criteria sent the RFC-3501 way (observed end-to-end while testing
        // DMARC delivery), even when CHARSET UTF-8 is declared. The
        // Gmail-specific extension `X-GM-RAW` accepts a Gmail-search-language
        // query and behaves like the web UI search box — this is what every
        // working Gmail IMAP client falls back to. We detect the provider
        // from the configured IMAP host and route string criteria through
        // X-GM-RAW on Gmail; other providers keep RFC-3501 + CHARSET UTF-8.
        let is_gmail = self.config.imap_host.to_lowercase().contains("gmail");

        let mut criteria = String::new();
        let mut has_string_criteria = false;
        let mut gmail_raw_terms: Vec<String> = Vec::new();

        // X-GM-RAW terms are composed by gmail_search_term(): bare tokens
        // stay UNQUOTED (a quoted value is an exact-phrase match in the
        // Gmail search language and does not match e.g. a domain prefix),
        // phrases stay quoted, non-expressible values are refused loudly.
        // IMAP-level escaping of the whole X-GM-RAW argument happens once,
        // at the composition site below (escape_imap_literal(&raw)).
        let push_gmail =
            |terms: &mut Vec<String>, key: &str, value: &str| -> Result<(), McpError> {
                terms.push(gmail_search_term(Some(key), value)?);
                Ok(())
            };

        if let Some(ref subject) = params.subject {
            has_string_criteria = true;
            if is_gmail {
                push_gmail(&mut gmail_raw_terms, "subject", subject)?;
            } else {
                criteria.push_str(&format!("SUBJECT \"{}\" ", escape_imap_literal(subject)));
            }
        }
        if let Some(ref from) = params.from {
            has_string_criteria = true;
            if is_gmail {
                push_gmail(&mut gmail_raw_terms, "from", from)?;
            } else {
                criteria.push_str(&format!("FROM \"{}\" ", escape_imap_literal(from)));
            }
        }
        if let Some(ref body) = params.body {
            has_string_criteria = true;
            if is_gmail {
                // Gmail bare term searches body+subject; this matches the
                // user's intent better than SEARCH BODY. Quoting follows
                // gmail_search_term(): bare token = word match, otherwise
                // exact phrase.
                gmail_raw_terms.push(gmail_search_term(None, body)?);
            } else {
                criteria.push_str(&format!("BODY \"{}\" ", escape_imap_literal(body)));
            }
        }
        if let Some(ref to) = params.to {
            has_string_criteria = true;
            if is_gmail {
                push_gmail(&mut gmail_raw_terms, "to", to)?;
            } else {
                criteria.push_str(&format!("TO \"{}\" ", escape_imap_literal(to)));
            }
        }
        if let Some(ref cc) = params.cc {
            has_string_criteria = true;
            if is_gmail {
                push_gmail(&mut gmail_raw_terms, "cc", cc)?;
            } else {
                criteria.push_str(&format!("CC \"{}\" ", escape_imap_literal(cc)));
            }
        }
        if let Some(ref before) = params.before {
            criteria.push_str(&format!("BEFORE {} ", normalize_imap_date(before)?));
        }
        if let Some(ref since) = params.since {
            criteria.push_str(&format!("SINCE {} ", normalize_imap_date(since)?));
        }
        if let Some(ref header) = params.header {
            // RFC-3501 HEADER criterion: `HEADER <field-name> <quoted-value>`.
            // Split the field from the value; validate the field as a token and
            // quote+escape the value so neither can inject extra SEARCH keys.
            has_string_criteria = true;
            let (field, value) = match header.split_once(char::is_whitespace) {
                Some((f, v)) => (f, v.trim()),
                None => (header.as_str(), ""),
            };
            criteria.push_str(&format!(
                "HEADER {} \"{}\" ",
                validate_header_name(field)?,
                escape_imap_literal(value)
            ));
        }
        if let Some(ref uid_range) = params.uid_range {
            criteria.push_str(&format!("UID {} ", validate_sequence_set(uid_range)?));
        }

        // Compose the final criteria. On Gmail with X-GM-RAW we join terms
        // with spaces (implicit AND in Gmail search), and merge with any
        // numeric/date predicates the RFC-3501 path produced.
        if is_gmail && !gmail_raw_terms.is_empty() {
            let raw = gmail_raw_terms.join(" ");
            criteria = if criteria.is_empty() {
                format!("X-GM-RAW \"{}\"", escape_imap_literal(&raw))
            } else {
                format!("X-GM-RAW \"{}\" {criteria}", escape_imap_literal(&raw))
            };
        } else if criteria.is_empty() {
            criteria = "ALL".to_string();
        } else if has_string_criteria {
            criteria = format!("CHARSET UTF-8 {criteria}");
        }

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, &criteria, self.imap_operation_timeout())
                .await?;

        let mut uid_list: Vec<u32> = uids.into_iter().collect();
        uid_list.sort_by(|a, b| b.cmp(a));
        uid_list.truncate(limit as usize);

        if uid_list.is_empty() {
            return Ok(CallToolResult::success(vec![
                Content::json(Vec::<EmailSummary>::new())
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ]));
        }

        let uid_set = uid_list
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetches = conn
            .uid_fetch(&uid_set, "(ENVELOPE FLAGS RFC822.SIZE)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let emails: Vec<EmailSummary> = fetches_vec
            .into_iter()
            .filter_map(|f| f.uid.map(|uid| message::extract_summary(uid, &f)))
            .collect();

        Ok(CallToolResult::success(vec![
            Content::json(&emails).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    // ── Send and drafts ─────────────────────────────────────────

    #[tool(
        description = "Send an email via SMTP. `to`, `cc` and `bcc` accept a single address or a comma/semicolon separated list; Bcc recipients go in the SMTP envelope only and are never written in the message headers (RFC 5322 §3.6.3)"
    )]
    async fn send_email(
        &self,
        params: Parameters<SendEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        use lettre::AsyncTransport;

        let params = params.0;

        Self::validate_from_override(
            params.from.as_deref(),
            self.provider.default_from(),
            self.provider.allowed_from(),
        )?;
        let from_addr: &str = params
            .from
            .as_deref()
            .unwrap_or_else(|| self.provider.default_from());

        let email = self.compose_send_email(&params)?;

        // Get raw bytes for IMAP append BEFORE sending
        let raw = email.formatted();

        let mailer = self.get_smtp_transport().await?;

        // Try send; on transient failure, rebuild transport and retry once.
        // Failure descriptions are CLASSIFIED (severity + numeric code
        // only): the raw server text may quote the refused recipient — and
        // a Bcc recipient is envelope-only — so it never reaches the log
        // or the client, on the initial failure nor on the retry.
        let send_result = mailer.send(email.clone()).await;
        let send_result = match send_result {
            Ok(_) => Ok(()),
            Err(e) if e.is_transient() => {
                tracing::warn!(
                    "SMTP send failed ({}); rebuilding transport and retrying once",
                    classify_smtp_send_failure(&e)
                );
                self.rebuild_smtp_transport().await?;
                let mailer = self.get_smtp_transport().await?;
                mailer.send(email).await.map(|_| ())
            }
            Err(e) => Err(e),
        };
        send_result.map_err(|e| {
            McpError::internal_error(
                format!("SMTP send failed: {}", classify_smtp_send_failure(&e)),
                None,
            )
        })?;

        // Append actual email to Sent folder via IMAP, unless the SMTP server
        // already auto-saves (Gmail/Outlook/Office 365). The resolved mode is
        // configured once via SaveSentMode::resolve at config load time.
        let save_sent_executed = match self.provider.save_sent_mode() {
            crate::config::SaveSentMode::Always => {
                if let Ok(mut conn) = self.get_imap_connection().await {
                    if let Some(sent_name) = self
                        .find_special_folder(&mut conn, folder::find_sent_folder)
                        .await
                    {
                        let _ = conn
                            .append(&sent_name, Default::default(), None, &raw)
                            .await;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            crate::config::SaveSentMode::Never => false,
        };

        // No raw recipient text and no Bcc addresses in logs — only
        // per-field entry counts.
        tracing::info!(
            target: "audit::send_email",
            from = %from_addr,
            to_recipients = crate::recipients::entry_count(&params.to),
            cc_recipients = params
                .cc
                .as_deref()
                .map(crate::recipients::entry_count)
                .unwrap_or(0),
            bcc_recipients = params
                .bcc
                .as_deref()
                .map(crate::recipients::entry_count)
                .unwrap_or(0),
            subject_len = params.subject.len(),
            in_reply_to = ?params.in_reply_to,
            save_sent_executed,
            "send_email completed"
        );

        Ok(CallToolResult::success(vec![Content::text(
            "Email sent successfully",
        )]))
    }

    #[tool(description = "List draft emails", annotations(read_only_hint = true))]
    async fn list_drafts(
        &self,
        params: Parameters<ListDraftsParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let limit = params.limit.unwrap_or(20);

        let mut conn = self.get_imap_connection().await?;
        let drafts_name = self
            .find_special_folder(&mut conn, folder::find_drafts_folder)
            .await
            .ok_or_else(|| McpError::internal_error("Drafts folder not found", None))?;

        conn.select(&drafts_name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, "ALL", self.imap_operation_timeout()).await?;

        let mut uid_list: Vec<u32> = uids.into_iter().collect();
        uid_list.sort_by(|a, b| b.cmp(a));
        uid_list.truncate(limit as usize);

        if uid_list.is_empty() {
            return Ok(CallToolResult::success(vec![
                Content::json(Vec::<EmailSummary>::new())
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ]));
        }

        let uid_set = uid_list
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let fetches = conn
            .uid_fetch(&uid_set, "(ENVELOPE FLAGS RFC822.SIZE)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let drafts: Vec<EmailSummary> = fetches_vec
            .into_iter()
            .filter_map(|f| f.uid.map(|uid| message::extract_summary(uid, &f)))
            .collect();

        Ok(CallToolResult::success(vec![
            Content::json(&drafts).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    #[tool(
        description = "Create a new draft email. `to`, `cc` and `bcc` accept a single address or a comma/semicolon separated list; Cc and Bcc headers are stored in the private IMAP draft (Bcc included, so the draft stays editable; it is stripped when sending)"
    )]
    async fn create_draft(
        &self,
        params: Parameters<CreateDraftParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let email = self.compose_create_draft(&params)?;

        let raw = email.formatted();

        let mut conn = self.get_imap_connection().await?;
        let drafts_name = self
            .find_special_folder(&mut conn, folder::find_drafts_folder)
            .await
            .ok_or_else(|| McpError::internal_error("Drafts folder not found", None))?;

        conn.append(&drafts_name, Default::default(), None, &raw)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(
            "Draft created",
        )]))
    }

    #[tool(
        description = "Update an existing draft: the new version is APPENDed first and only after confirmed success the old draft is removed with a targeted UID EXPUNGE; without UIDPLUS the old draft is preserved (partial substitution, never a global EXPUNGE). Returns the new UID when the server provides APPENDUID. `to`, `cc` and `bcc` accept a single address or a comma/semicolon separated list and are FULL REPLACEMENT: omitting `cc`/`bcc` removes those headers from the new draft (Cc and Bcc are stored in the private draft, Bcc included; it is stripped when sending)"
    )]
    async fn update_draft(
        &self,
        params: Parameters<UpdateDraftParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let old_uid = params.uid;

        // 1. Compose and validate EVERYTHING first: with invalid input no
        // destructive operation is even attempted (a delete-before-validate
        // order would destroy ready drafts on invalid input).
        let email = self.compose_update_draft(&params)?;
        let raw = email.formatted();

        let mut conn = self.get_imap_connection().await?;
        let drafts_name = self
            .find_special_folder(&mut conn, folder::find_drafts_folder)
            .await
            .ok_or_else(|| McpError::internal_error("Drafts folder not found", None))?;

        conn.select(&drafts_name)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // 2. APPEND first — completely non-destructive. On a definite failure
        // or on an UNCERTAIN outcome the old draft stays untouched, and there
        // is NO blind retry. The append runs on a DEDICATED connection (never
        // returned to the pool): if it is left waiting for a literal or in an
        // uncertain protocol state it is simply discarded on drop, instead of
        // going back to the pool as "valid".
        let mut append_session = self.dedicated_imap_session().await?;
        let appended = append_new_draft(
            &mut append_session,
            &drafts_name,
            &raw,
            self.imap_operation_timeout(),
        )
        .await?;
        // La connessione dedicata non serve piu': viene chiusa e scartata,
        // qualunque sia lo stato di protocollo raggiunto.
        drop(append_session);
        let new_uid_text = appended
            .new_uid
            .map(|u| u.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // 3. Only after a CONFIRMED append success: remove the old draft,
        // with a targeted UID EXPUNGE on that single UID only.
        let has_uidplus = conn
            .capabilities()
            .await
            .map_err(|e| {
                // The APPEND is ALREADY confirmed here: the error must say
                // that the new draft is saved and the old one is untouched.
                McpError::internal_error(
                    format!(
                        "new draft APPENDED successfully (uid={new_uid_text}), but the old draft uid={old_uid} was NOT marked or removed: the UIDPLUS capability check failed ({e}); state: BOTH drafts present, no retry",
                    ),
                    None,
                )
            })?
            .has_str("UIDPLUS");

        if !has_uidplus {
            // Without UIDPLUS there is no safe way to remove only the old
            // draft: expunge() is GLOBAL and would also destroy any other
            // message already marked \\Deleted in the folder. The old draft
            // is preserved and the partial substitution is declared.
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Draft appended: new uid={}. PARTIAL SUBSTITUTION: old draft uid={} preserved (server does not advertise UIDPLUS, so a targeted UID EXPUNGE is impossible and a global EXPUNGE is never used).",
                new_uid_text, old_uid
            ))]));
        }

        conn.uid_store(&old_uid.to_string(), "+FLAGS (\\Deleted)")
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "new draft APPENDED successfully (uid={}); the old draft uid={} was NOT removed (no expunge attempted) and its \\Deleted mark MAY OR MAY NOT have been applied: {e}; state: new draft safe, no retry",
                        new_uid_text, old_uid
                    ),
                    None,
                )
            })?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "new draft APPENDED successfully (uid={}); the old draft uid={} was NOT removed (no expunge attempted) and its \\Deleted mark MAY OR MAY NOT have been applied: {e}; state: new draft safe, no retry",
                        new_uid_text, old_uid
                    ),
                    None,
                )
            })?;

        conn.uid_expunge(old_uid.to_string())
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "new draft APPENDED successfully (uid={}); the old draft uid={} removal outcome is UNCERTAIN: the targeted UID EXPUNGE MAY have been applied before its response was lost ({e}); do NOT assume the old draft still exists; no retry",
                        new_uid_text, old_uid
                    ),
                    None,
                )
            })?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "new draft APPENDED successfully (uid={}); the old draft uid={} removal outcome is UNCERTAIN: the targeted UID EXPUNGE MAY have been applied before its response was lost ({e}); do NOT assume the old draft still exists; no retry",
                        new_uid_text, old_uid
                    ),
                    None,
                )
            })?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Draft updated: new uid={} now holds the content; old uid={} removed via targeted UID EXPUNGE (other drafts untouched).",
            new_uid_text, old_uid
        ))]))
    }

    // ── Composizione messaggi in uscita (condivisa) ─────────────
    //
    // I TRE percorsi di costruzione del corpo (send_email, create_draft,
    // update_draft) passano tutti da `crate::attachments::compose_body`:

    // mixed esterno con alternative interno quando servono sia html sia
    // allegati, formati storici (singlepart / alternative) quando no.
    // I metodi sono PUBBLICI per essere esercitati dai test di composizione:
    // non fanno NESSUNA I/O di rete (nessun SMTP/IMAP).

    /// Early guard: the textual body and headers must not already exceed the
    /// MIME ceiling BEFORE composing and serializing the whole message (this
    /// avoids large allocations just to discover the limit too late).
    /// The EXACT check on the serialized MIME stays in `finalize_composed`.
    fn preflight_body_headers(
        body: &str,
        html: Option<&str>,
        subject: &str,
        to: &str,
        from: &str,
        extra_headers: &[&str],
        max_mime_bytes: u64,
    ) -> Result<(), McpError> {
        let mut total = body.len() as u64
            + html.map(|h| h.len() as u64).unwrap_or(0)
            + subject.len() as u64
            + to.len() as u64
            + from.len() as u64;
        for h in extra_headers {
            total += h.len() as u64;
        }
        if total > max_mime_bytes {
            return Err(McpError::internal_error(
                format!(
                    "body/headers size {total} already exceeds the MIME limit {max_mime_bytes} (EMAIL_ATTACH_MAX_MIME_BYTES): rejected BEFORE composing (preliminary guard); the exact serialized-size check stays in place"
                ),
                None,
            ));
        }
        Ok(())
    }

    /// Prepara gli allegati richiesti: errore esplicito se `EMAIL_ATTACH_DIR`
    /// non è configurata (allegati disabilitati, mai fallback a cwd/home).
    fn prepare_attachments(
        &self,
        attachments: Option<&[AttachmentParam]>,
    ) -> Result<Vec<crate::attachments::PreparedAttachment>, McpError> {
        let Some(list) = attachments else {
            return Ok(Vec::new());
        };
        if list.is_empty() {
            // `[]` and omitted must behave the same EVEN without a configured
            // root: there is no attachment to read, so the EMAIL_ATTACH_DIR
            // gate does not apply. A non-empty list without a root stays
            // rejected.
            return Ok(Vec::new());
        }
        let Some(dir) = self.config.attachment_dir.as_ref() else {
            return Err(McpError::internal_error(
                "attachments are disabled: EMAIL_ATTACH_DIR is not configured; \
                 set it to a dedicated directory to enable outgoing attachments \
                 (no fallback to cwd or home)",
                None,
            ));
        };
        let inputs = list.iter().map(|a| crate::attachments::AttachmentInput {
            path: &a.path,
            filename: a.filename.as_deref(),
            mime: a.mime.as_deref(),
        });
        crate::attachments::prepare(
            dir,
            inputs,
            crate::attachments::AttachmentLimits {
                max_mime_bytes: self.config.attachment_max_mime_bytes,
                max_count: self.config.attachment_max_count,
            },
        )
        .map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    /// Finalizza il Message e applica il tetto ESATTO sul MIME serializzato
    /// (header e transfer encoding inclusi).
    fn finalize_composed(
        builder: lettre::message::MessageBuilder,
        composed: crate::attachments::ComposedBody,
        max_mime_bytes: u64,
    ) -> Result<lettre::Message, McpError> {
        let built = match composed {
            crate::attachments::ComposedBody::Single(part) => builder.singlepart(part),
            crate::attachments::ComposedBody::Multi(parts) => builder.multipart(parts),
        }
        .map_err(|e| McpError::internal_error(format!("Failed to build email: {e}"), None))?;
        let raw_len = built.formatted().len() as u64;
        if raw_len > max_mime_bytes {
            return Err(McpError::internal_error(
                format!(
                    "serialized MIME size {raw_len} exceeds attachment limit {max_mime_bytes} \
                     (EMAIL_ATTACH_MAX_MIME_BYTES)"
                ),
                None,
            ));
        }
        Ok(built)
    }

    /// Corpo+headers di `send_email` SENZA rete: usato dall'handler e dai test.
    pub fn compose_send_email(
        &self,
        params: &SendEmailParams,
    ) -> Result<lettre::Message, McpError> {
        Self::validate_from_override(
            params.from.as_deref(),
            self.provider.default_from(),
            self.provider.allowed_from(),
        )?;
        let from_addr: &str = params
            .from
            .as_deref()
            .unwrap_or_else(|| self.provider.default_from());
        // The preflight comes BEFORE the builder and the parses: the headers
        // are still un-cloned strings here — it is exactly that allocation
        // (clones and builder) that the guard avoids.
        Self::preflight_body_headers(
            params.body.as_deref().unwrap_or(""),
            params.html.as_deref(),
            &params.subject,
            &params.to,
            from_addr,
            &[
                params.cc.as_deref().unwrap_or(""),
                params.bcc.as_deref().unwrap_or(""),
                params.reply_to.as_deref().unwrap_or(""),
                params.in_reply_to.as_deref().unwrap_or(""),
                params.references.as_deref().unwrap_or(""),
            ],
            self.config.attachment_max_mime_bytes,
        )?;
        // `to`, `cc` and `bcc` accept comma/semicolon separated lists;
        // the whole list is validated (field + 1-based entry index in the
        // error) before the builder, the attachments and any I/O.
        let recipients = crate::recipients::parse_recipients(
            &params.to,
            params.cc.as_deref(),
            params.bcc.as_deref(),
        )?;
        // The Bcc recipients ride the SMTP ENVELOPE only: lettre derives
        // the envelope from the To+Cc+Bcc headers at build time and its
        // default `drop_bcc` then removes the Bcc header from the
        // serialized message (RFC 5322 §3.6.3) — verified by the fake
        // SMTP test: RCPT TO carries to+cc+bcc, DATA has no Bcc header.
        let mut builder =
            crate::recipients::apply_recipients(
                lettre::Message::builder()
                    .from(from_addr.parse().map_err(|e| {
                        McpError::internal_error(format!("Invalid from: {e}"), None)
                    })?)
                    .subject(&params.subject),
                recipients,
            );
        if let Some(ref reply_to) = params.reply_to {
            builder =
                builder.reply_to(reply_to.parse().map_err(|e| {
                    McpError::internal_error(format!("Invalid reply_to: {e}"), None)
                })?);
        }
        // Threading headers
        if let Some(ref irt) = params.in_reply_to {
            builder = builder.in_reply_to(irt.clone());
        }
        if let Some(ref refs) = params.references {
            builder = builder.references(refs.clone());
        }
        let prepared = self.prepare_attachments(params.attachments.as_deref())?;
        let composed = crate::attachments::compose_body(
            params.body.clone().unwrap_or_default(),
            params.html.clone(),
            &prepared,
        );
        Self::finalize_composed(builder, composed, self.config.attachment_max_mime_bytes)
    }

    /// Corpo+headers di `create_draft` SENZA rete.
    pub fn compose_create_draft(
        &self,
        params: &CreateDraftParams,
    ) -> Result<lettre::Message, McpError> {
        let from_addr = self.provider.default_from();
        // Preflight BEFORE the builder and the parses — cc and bcc included
        // in the size ceiling.
        Self::preflight_body_headers(
            params.body.as_deref().unwrap_or(""),
            params.html.as_deref(),
            &params.subject,
            &params.to,
            from_addr,
            &[
                params.cc.as_deref().unwrap_or(""),
                params.bcc.as_deref().unwrap_or(""),
            ],
            self.config.attachment_max_mime_bytes,
        )?;
        // Liste di destinatari (to/cc/bcc), validate per intero
        // (campo + indice) prima di builder, allegati e APPEND.
        let recipients = crate::recipients::parse_recipients(
            &params.to,
            params.cc.as_deref(),
            params.bcc.as_deref(),
        )?;
        // The draft is PRIVATE to the account, so Bcc is KEPT in the
        // stored headers (`keep_bcc`: lettre's default would drop it at
        // build time) — the draft stays fully editable. Bcc is stripped
        // from the message only when SENDING (see compose_send_email).
        let builder =
            crate::recipients::apply_recipients(
                lettre::Message::builder()
                    .from(from_addr.parse().map_err(|e| {
                        McpError::internal_error(format!("Invalid from: {e}"), None)
                    })?)
                    .keep_bcc()
                    .subject(&params.subject),
                recipients,
            );
        let prepared = self.prepare_attachments(params.attachments.as_deref())?;
        let composed = crate::attachments::compose_body(
            params.body.clone().unwrap_or_default(),
            params.html.clone(),
            &prepared,
        );
        Self::finalize_composed(builder, composed, self.config.attachment_max_mime_bytes)
    }

    /// Corpo+headers di `update_draft` SENZA rete: nessuna conservazione
    /// implicita degli allegati della bozza precedente (omesso o `[]` =
    /// bozza senza allegati). Sostituzione COMPLETA anche per cc/bcc:
    /// omessi = header assenti nella nuova bozza.
    pub fn compose_update_draft(
        &self,
        params: &UpdateDraftParams,
    ) -> Result<lettre::Message, McpError> {
        let from_addr = self.provider.default_from();
        // Preflight BEFORE the builder and the parses — cc and bcc included
        // in the size ceiling.
        Self::preflight_body_headers(
            params.body.as_deref().unwrap_or(""),
            params.html.as_deref(),
            &params.subject,
            &params.to,
            from_addr,
            &[
                params.cc.as_deref().unwrap_or(""),
                params.bcc.as_deref().unwrap_or(""),
            ],
            self.config.attachment_max_mime_bytes,
        )?;
        // Liste di destinatari (to/cc/bcc), validate per intero
        // (campo + indice) prima di builder, allegati, APPEND, STORE ed
        // EXPUNGE. cc/bcc omessi = campi rimossi (sostituzione completa).
        let recipients = crate::recipients::parse_recipients(
            &params.to,
            params.cc.as_deref(),
            params.bcc.as_deref(),
        )?;
        // come compose_create_draft: bozza privata, Bcc conservato.
        let builder =
            crate::recipients::apply_recipients(
                lettre::Message::builder()
                    .from(from_addr.parse().map_err(|e| {
                        McpError::internal_error(format!("Invalid from: {e}"), None)
                    })?)
                    .keep_bcc()
                    .subject(&params.subject),
                recipients,
            );
        let prepared = self.prepare_attachments(params.attachments.as_deref())?;
        let composed = crate::attachments::compose_body(
            params.body.clone().unwrap_or_default(),
            params.html.clone(),
            &prepared,
        );
        Self::finalize_composed(builder, composed, self.config.attachment_max_mime_bytes)
    }

    // ── Email operations ────────────────────────────────────────

    /// SAFE removal of messages marked \Deleted (without UIDPLUS there is no
    /// expunge at all).
    ///
    /// With UIDPLUS: a targeted UID EXPUNGE on the requested uids only.
    /// Without UIDPLUS: NO expunge — a global one removes every message
    /// marked \Deleted, and a prior snapshot of the state (SEARCH DELETED)
    /// does not close the window in which another client marks others. The
    /// requested messages stay marked and the response states it.
    async fn expunge_marked_uids(
        &self,
        conn: &mut crate::pool::TlsImapSession,
        requested: &[u32],
    ) -> Result<ExpungeOutcome, McpError> {
        // Every error declares ONLY what is known ("NOT expunged" is true
        // only while the expunge has never been sent; if the response is
        // lost, the removal is UNCERTAIN and may have been applied).
        let has_uidplus = conn
            .capabilities()
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!(
                        "removal NOT attempted: the UIDPLUS capability check failed ({e}); the requested messages remain marked \\Deleted and NOT expunged; no retry"
                    ),
                    None,
                )
            })?
            .has_str("UIDPLUS");

        if has_uidplus {
            let uid_set = requested
                .iter()
                .map(|u| u.to_string())
                .collect::<Vec<_>>()
                .join(",");
            conn.uid_expunge(uid_set)
                .await
                .map_err(|e| {
                    McpError::internal_error(
                        format!(
                            "removal outcome UNCERTAIN: the UID EXPUNGE command failed while being sent ({e}); it may or may not have been applied; do NOT assume the messages still exist, nor that they are still merely marked \\Deleted; no retry"
                        ),
                        None,
                    )
                })?
                .try_collect::<Vec<_>>()
                .await
                .map_err(|e| {
                    McpError::internal_error(
                        format!(
                            "removal outcome UNCERTAIN: the UID EXPUNGE may have been applied before its response was lost ({e}); do NOT assume the marked messages still exist; no retry"
                        ),
                        None,
                    )
                })?;
            return Ok(ExpungeOutcome::Targeted);
        }

        // Without UIDPLUS there is no expunge. Not even when a SEARCH
        // DELETED snapshot showed a matching set: between SEARCH and
        // EXPUNGE another client can mark other messages, and the global
        // expunge would take those away too. The requested marking stays
        // and the response declares the deferred removal.
        let _ = requested;
        Ok(ExpungeOutcome::DeferredMarkedOnly)
    }

    #[tool(description = "Delete an email by UID")]
    async fn delete_email(
        &self,
        params: Parameters<DeleteEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_store(&params.uid.to_string(), "+FLAGS (\\Deleted)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        match self.expunge_marked_uids(&mut conn, &[params.uid]).await? {
            ExpungeOutcome::Targeted => Ok(CallToolResult::success(vec![Content::text(format!(
                "Email uid={} deleted (targeted UID EXPUNGE; other \\Deleted messages untouched)",
                params.uid
            ))])),
            ExpungeOutcome::DeferredMarkedOnly => {
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Email uid={} marked \\Deleted but NOT expunged: the server does not advertise UIDPLUS, so a targeted removal is unavailable and a global EXPUNGE is never used (it would also remove \\Deleted messages from other clients). The mark remains; the message will disappear when the folder is next expunged.",
                    params.uid
                ))]))
            }
        }
    }

    #[tool(description = "Move an email between folders")]
    async fn move_email(
        &self,
        params: Parameters<MoveEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let from_folder = params.from_folder.as_deref().unwrap_or("INBOX");

        // Resolve to_folder to actual IMAP name (handles UTF-7 + delimiter)
        let resolved_to = self.resolve_folder(&params.to_folder).await?;

        let resolved_from = self.resolve_folder(from_folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_from)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_mv(&params.uid.to_string(), &resolved_to)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email uid={} moved to {} (IMAP: {})",
            params.uid, params.to_folder, resolved_to
        ))]))
    }

    #[tool(description = "Copy an email to another folder")]
    async fn copy_email(
        &self,
        params: Parameters<CopyEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let from_folder = params.from_folder.as_deref().unwrap_or("INBOX");

        // Resolve to_folder to actual IMAP name
        let resolved_to = self.resolve_folder(&params.to_folder).await?;

        let resolved_from = self.resolve_folder(from_folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_from)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_copy(&params.uid.to_string(), &resolved_to)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email uid={} copied to {} (IMAP: {})",
            params.uid, params.to_folder, resolved_to
        ))]))
    }

    #[tool(description = "Star or unstar an email")]
    async fn flag_email(
        &self,
        params: Parameters<FlagEmailParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let flag_op = if params.flagged {
            "+FLAGS (\\Flagged)"
        } else {
            "-FLAGS (\\Flagged)"
        };

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_store(&params.uid.to_string(), flag_op)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email uid={} {}",
            params.uid,
            if params.flagged {
                "flagged"
            } else {
                "unflagged"
            }
        ))]))
    }

    #[tool(description = "Mark an email as read or unread")]
    async fn mark_seen(
        &self,
        params: Parameters<MarkSeenParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let flag_op = if params.seen {
            "+FLAGS (\\Seen)"
        } else {
            "-FLAGS (\\Seen)"
        };

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_store(&params.uid.to_string(), flag_op)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Email uid={} marked as {}",
            params.uid,
            if params.seen { "read" } else { "unread" }
        ))]))
    }

    #[tool(description = "Mark multiple emails as read or unread in one operation")]
    async fn batch_mark_seen(
        &self,
        params: Parameters<BatchMarkSeenParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let flag_op = if params.seen {
            "+FLAGS (\\Seen)"
        } else {
            "-FLAGS (\\Seen)"
        };

        let uid_set = params
            .uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_store(&uid_set, flag_op)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Marked {} emails as {}",
            params.uids.len(),
            if params.seen { "read" } else { "unread" }
        ))]))
    }

    #[tool(description = "Delete multiple emails in one operation")]
    async fn batch_delete(
        &self,
        params: Parameters<BatchDeleteParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let uid_set = params
            .uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        conn.uid_store(&uid_set, "+FLAGS (\\Deleted)")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        match self.expunge_marked_uids(&mut conn, &params.uids).await? {
            ExpungeOutcome::Targeted => Ok(CallToolResult::success(vec![Content::text(format!(
                "Deleted {} emails (targeted UID EXPUNGE of uid set {uid_set}; other \\Deleted messages untouched)",
                params.uids.len()
            ))])),
            ExpungeOutcome::DeferredMarkedOnly => {
                Ok(CallToolResult::success(vec![Content::text(format!(
                    "Deleted 0 emails: {uid_set} marked \\Deleted but NOT expunged — the server does not advertise UIDPLUS, so a targeted removal is unavailable and a global EXPUNGE is never used (it would also remove \\Deleted messages from other clients). The marks remain; the messages will disappear when the folder is next expunged.",
                ))]))
            }
        }
    }

    #[tool(description = "Download an email attachment as base64 or save it to disk")]
    async fn download_attachment(
        &self,
        params: Parameters<DownloadAttachmentParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches = conn
            .uid_fetch(&params.uid.to_string(), "(BODY.PEEK[])")
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetch = fetches_vec
            .iter()
            .find(|f| f.uid == Some(params.uid))
            .ok_or_else(|| {
                McpError::internal_error(format!("Email not found: uid={}", params.uid), None)
            })?;

        let raw = fetch
            .body()
            .ok_or_else(|| McpError::internal_error("No email body in response", None))?;

        let data = message::extract_attachment_bytes(raw, &params.part_id)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        if let Some(save_path) = params.save_path {
            let dest = resolve_save_path(&download_base_dir(), &save_path)?;
            if let Some(parent) = dest.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::write(&dest, &data).map_err(|e| McpError::internal_error(e.to_string(), None))?;
            return Ok(CallToolResult::success(vec![Content::text(format!(
                "Saved to {} ({} bytes)",
                dest.display(),
                data.len()
            ))]));
        }

        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

        Ok(CallToolResult::success(vec![Content::text(b64)]))
    }

    #[tool(description = "Move an entire email thread by subject")]
    async fn move_thread(
        &self,
        params: Parameters<MoveThreadParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let normalized = folder::normalize_thread_subject(&params.subject);

        // Resolve to_folder to actual IMAP name (handles UTF-7 + delimiter)
        let resolved_to = self.resolve_folder(&params.to_folder).await?;

        let resolved_from = self.resolve_folder(&params.from_folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_from)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut criteria = format!("SUBJECT \"{}\"", escape_imap_literal(&normalized));
        if let Some(ref from) = params.from_address {
            criteria.push_str(&format!(" FROM \"{}\"", escape_imap_literal(from)));
        }

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, &criteria, self.imap_operation_timeout())
                .await?;

        if uids.is_empty() {
            return Ok(CallToolResult::success(vec![Content::text(
                "No emails found for this thread",
            )]));
        }

        let uid_set: String = uids
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");

        conn.uid_mv(&uid_set, &resolved_to)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Moved {} emails to {} (IMAP: {})",
            uids.len(),
            params.to_folder,
            resolved_to
        ))]))
    }

    // ── IDLE and advanced ───────────────────────────────────────

    #[tool(
        description = "Wait for new emails using IMAP IDLE (push notifications). Returns after timeout or when new mail arrives.",
        annotations(read_only_hint = true)
    )]
    async fn idle_wait(
        &self,
        params: Parameters<IdleWaitParams>,
    ) -> Result<CallToolResult, McpError> {
        // NOTE: IMAP IDLE requires taking ownership of the session, which is
        // incompatible with connection pooling. This implementation uses a
        // polling approach: it records the initial UID count, then polls with
        // NOOP at intervals until a change is detected or timeout is reached.
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let timeout_secs = params.timeout_secs.unwrap_or(60).min(300);

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let initial_count =
            search_boundary::uid_search(&mut conn, "ALL", self.imap_operation_timeout())
                .await?
                .len();

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(timeout_secs);
        let poll_interval = std::time::Duration::from_secs(5);

        loop {
            tokio::time::sleep(poll_interval).await;

            conn.noop()
                .await
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;

            let current_count =
                search_boundary::uid_search(&mut conn, "ALL", self.imap_operation_timeout())
                    .await?
                    .len();

            if current_count != initial_count {
                return Ok(CallToolResult::success(vec![
                    Content::json(serde_json::json!({
                        "folder": folder,
                        "change_detected": true,
                        "initial_count": initial_count,
                        "current_count": current_count,
                        "elapsed_secs": start.elapsed().as_secs(),
                    }))
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]));
            }

            if start.elapsed() >= timeout {
                return Ok(CallToolResult::success(vec![
                    Content::json(serde_json::json!({
                        "folder": folder,
                        "change_detected": false,
                        "initial_count": initial_count,
                        "elapsed_secs": start.elapsed().as_secs(),
                        "timed_out": true,
                    }))
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
                ]));
            }
        }
    }

    #[tool(
        description = "List emails with custom headers (for threading analysis)",
        annotations(read_only_hint = true)
    )]
    async fn list_emails_with_headers(
        &self,
        params: Parameters<ListEmailsWithHeadersParams>,
    ) -> Result<CallToolResult, McpError> {
        let params = params.0;
        let folder = params.folder.as_deref().unwrap_or("INBOX");
        let limit = params.limit.unwrap_or(20);

        let resolved_folder = self.resolve_folder(folder).await?;
        let mut conn = self.get_imap_connection().await?;
        conn.select(&resolved_folder)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let mut search_criteria = String::new();
        if params.unseen_only.unwrap_or(false) {
            search_criteria.push_str("UNSEEN ");
        }
        if let Some(ref date) = params.since_date {
            search_criteria.push_str(&format!("SINCE {} ", normalize_imap_date(date)?));
        }
        if search_criteria.is_empty() {
            search_criteria = "ALL".to_string();
        }

        let uids: std::collections::HashSet<u32> =
            search_boundary::uid_search(&mut conn, &search_criteria, self.imap_operation_timeout())
                .await?;

        let mut uid_list: Vec<u32> = uids.into_iter().collect();
        uid_list.sort_by(|a, b| b.cmp(a));
        uid_list.truncate(limit as usize);

        if uid_list.is_empty() {
            return Ok(CallToolResult::success(vec![
                Content::json(Vec::<serde_json::Value>::new())
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?,
            ]));
        }

        // Build fetch items: ENVELOPE + requested headers. Validate every header
        // field-name so none can inject into BODY[HEADER.FIELDS (...)].
        for h in &params.headers {
            validate_header_name(h)?;
        }
        let header_fields = params.headers.join(" ");
        let fetch_items =
            format!("(ENVELOPE FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS ({header_fields})])");

        let uid_set = uid_list
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let fetches = conn
            .uid_fetch(&uid_set, &fetch_items)
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let fetches_vec: Vec<_> = fetches
            .try_collect()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        let unseen_only = params.unseen_only.unwrap_or(false);
        let results: Vec<serde_json::Value> = fetches_vec
            .into_iter()
            .filter_map(|f| {
                let uid = f.uid?;
                let summary = message::extract_summary(uid, &f);
                // The fetch asks for BODY[HEADER.FIELDS (...)] and the
                // server echoes that section back as
                // BodySection { section: Some(Full(Header)) }: only the
                // header() accessor matches that shape (body() matches
                // section: None / Rfc822 and returns None here).
                if unseen_only
                    && summary
                        .flags
                        .iter()
                        .any(|flag| crate::server::flag_is_seen(flag))
                {
                    // Belt-and-braces: a SEARCH UNSEEN that lies must not
                    // surface already-seen rows.
                    return None;
                }
                let headers_text = f
                    .header()
                    .map(|h| String::from_utf8_lossy(h).into_owned())
                    .unwrap_or_default();
                Some(serde_json::json!({
                    "uid": uid,
                    "subject": summary.subject,
                    "from": summary.from,
                    "date": summary.date,
                    "headers": headers_text,
                }))
            })
            .collect();

        Ok(CallToolResult::success(vec![
            Content::json(&results).map_err(|e| McpError::internal_error(e.to_string(), None))?,
        ]))
    }

    // ── email_doctor ────────────────────────────────────────────

    #[tool(
        description = "Read-only diagnostic of email configuration: config path, source/precedence, IMAP/SMTP provider classification, allowed_from list, save_sent mode, pool, audit log, required env presence. Never echoes credentials or env values.",
        annotations(read_only_hint = true)
    )]
    async fn email_doctor(&self) -> Result<CallToolResult, McpError> {
        // Provider classification: returns a coarse label without echoing the
        // actual host. "unset" if empty, "other" if no known suffix matches.
        fn classify_host(host: &str) -> &'static str {
            let h = host.to_lowercase();
            if h.is_empty() {
                "unset"
            } else if h.contains("gmail") {
                "gmail"
            } else if h.contains("outlook") {
                "outlook"
            } else if h.contains("office365") {
                "office365"
            } else if h.contains("proton") {
                "proton"
            } else {
                "other"
            }
        }

        // Resolve the config path by reusing the same logic EmailConfig::load
        // uses, so doctor never drifts from the binary's real load order
        // (EMAIL_CONFIG → ./email.toml → ~/.config/mcp-email-rs/email.toml).
        let config_path_active: Option<std::path::PathBuf> = EmailConfig::resolve_toml_path();
        let toml_present = config_path_active.as_ref().is_some_and(|p| p.exists());
        let toml_mode_octal: Option<String> = config_path_active
            .as_ref()
            .filter(|p| p.exists())
            .and_then(|p| std::fs::metadata(p).ok())
            .map(|m| {
                use std::os::unix::fs::PermissionsExt;
                format!("{:o}", m.permissions().mode() & 0o777)
            });

        // Env-only presence/value lookup. Values are NEVER echoed in the
        // output; only the key→state mapping is exposed.
        let env_status = |k: &str| {
            if std::env::var(k).is_ok() {
                "set"
            } else {
                "unset"
            }
        };

        // All email-relevant env vars. Useful for an operator to spot drift
        // between TOML and stale shell env without leaking any value.
        let email_env_keys = serde_json::json!({
            "EMAIL_CONFIG":               env_status("EMAIL_CONFIG"),
            "EMAIL_AUDIT_LOG":            env_status("EMAIL_AUDIT_LOG"),
            "EMAIL_PROVIDER":             env_status("EMAIL_PROVIDER"),
            "EMAIL_SAVE_SENT":            env_status("EMAIL_SAVE_SENT"),
            "EMAIL_POOL_MAX_CONNECTIONS": env_status("EMAIL_POOL_MAX_CONNECTIONS"),
            "EMAIL_POOL_IDLE_TIMEOUT":    env_status("EMAIL_POOL_IDLE_TIMEOUT"),
            "EMAIL_OPERATION_TIMEOUT":    env_status("EMAIL_OPERATION_TIMEOUT"),
            "IMAP_HOST":                  env_status("IMAP_HOST"),
            "IMAP_PORT":                  env_status("IMAP_PORT"),
            "IMAP_USER":                  env_status("IMAP_USER"),
            "IMAP_PASSWORD":              env_status("IMAP_PASSWORD"),
            "IMAP_AUTH":                  env_status("IMAP_AUTH"),
            "IMAP_TLS":                   env_status("IMAP_TLS"),
            "IMAP_TLS_REJECT_UNAUTHORIZED": env_status("IMAP_TLS_REJECT_UNAUTHORIZED"),
            "IMAP_XOAUTH2_TOKEN":         env_status("IMAP_XOAUTH2_TOKEN"),
            "SMTP_HOST":                  env_status("SMTP_HOST"),
            "SMTP_PORT":                  env_status("SMTP_PORT"),
            "SMTP_USER":                  env_status("SMTP_USER"),
            "SMTP_PASSWORD":              env_status("SMTP_PASSWORD"),
            "SMTP_STARTTLS":              env_status("SMTP_STARTTLS"),
            "SMTP_FROM_ADDRESS":          env_status("SMTP_FROM_ADDRESS"),
            "EMAIL_ATTACH_DIR":           env_status("EMAIL_ATTACH_DIR"),
            "EMAIL_ATTACH_MAX_MIME_BYTES": env_status("EMAIL_ATTACH_MAX_MIME_BYTES"),
            "EMAIL_ATTACH_MAX_COUNT":     env_status("EMAIL_ATTACH_MAX_COUNT"),
        });

        // Source/precedence: any email env key counts toward "env". TOML
        // precedence over ENV is only documented for IMAP/SMTP connection
        // fields (see EmailConfig::build_from). `EMAIL_SAVE_SENT` has env-wins
        // precedence over `smtp.save_sent` — that nuance is documented in
        // --help, not collapsed into this enum.
        let any_email_env_set = [
            "EMAIL_CONFIG",
            "EMAIL_AUDIT_LOG",
            "EMAIL_PROVIDER",
            "EMAIL_SAVE_SENT",
            "EMAIL_POOL_MAX_CONNECTIONS",
            "EMAIL_POOL_IDLE_TIMEOUT",
            "EMAIL_OPERATION_TIMEOUT",
            "IMAP_HOST",
            "IMAP_PORT",
            "IMAP_USER",
            "IMAP_PASSWORD",
            "IMAP_AUTH",
            "IMAP_TLS",
            "IMAP_TLS_REJECT_UNAUTHORIZED",
            "IMAP_XOAUTH2_TOKEN",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USER",
            "SMTP_PASSWORD",
            "SMTP_STARTTLS",
            "SMTP_FROM_ADDRESS",
            "EMAIL_ATTACH_DIR",
            "EMAIL_ATTACH_MAX_MIME_BYTES",
            "EMAIL_ATTACH_MAX_COUNT",
        ]
        .iter()
        .any(|k| std::env::var(k).is_ok());
        let config_source = match (toml_present, any_email_env_set) {
            (true, true) => "toml+env (TOML wins for IMAP/SMTP connection fields)",
            (true, false) => "toml",
            (false, true) => "env",
            (false, false) => "none",
        };

        let cfg = &self.config;
        let save_sent_mode = match cfg.smtp_save_sent {
            crate::config::SaveSentMode::Always => "always",
            crate::config::SaveSentMode::Never => "never",
        };

        Ok(CallToolResult::success(
            vec![Content::json(serde_json::json!({
            "success": true,
            "config_path_active": config_path_active,
            "toml_present": toml_present,
            "toml_mode_octal": toml_mode_octal,
            "config_source": config_source,
            "imap": {
                "host_classify": classify_host(&cfg.imap_host),
                "port": cfg.imap_port,
                "tls": cfg.imap_tls,
                "tls_reject_unauthorized": cfg.imap_tls_reject_unauthorized,
                "auth": format!("{:?}", cfg.imap_auth).to_lowercase(),
                "user_set": !cfg.imap_user.is_empty(),
                "password_set": !cfg.imap_password.is_empty(),
                "xoauth2_token_set": cfg.imap_xoauth2_token.as_ref().is_some_and(|t| !t.is_empty()),
                "sanity": "not_checked"
            },
            "smtp": {
                "host_classify": classify_host(&cfg.smtp_host),
                "port": cfg.smtp_port,
                "starttls": cfg.smtp_starttls,
                "user_set": !cfg.smtp_user.is_empty(),
                "password_set": !cfg.smtp_password.is_empty(),
                "from_address_set": !cfg.smtp_from_address.is_empty(),
                "save_sent_mode": save_sent_mode,
                "allowed_from": cfg.smtp_allowed_from,
                "allowed_from_count": cfg.smtp_allowed_from.len(),
                "sanity": "not_checked"
            },
            "pool": {
                "max_connections": cfg.pool_max_connections,
                "idle_timeout_secs": cfg.pool_idle_timeout_secs
            },
            "operation_timeout_secs": cfg.operation_timeout_secs,
            "audit_log": {
                "env_configured": std::env::var("EMAIL_AUDIT_LOG").is_ok(),
                "path": std::env::var("EMAIL_AUDIT_LOG").ok()
            },
            "email_env_keys": email_env_keys
        })).map_err(|e| McpError::internal_error(e.to_string(), None))?],
        ))
    }
}

// ── Helper methods ──────────────────────────────────────────────

impl EmailServer {
    /// Timeout operativo delle singole operazioni IMAP, dalla configurazione.
    fn imap_operation_timeout(&self) -> std::time::Duration {
        self.provider.imap_pool().operation_timeout()
    }

    async fn get_imap_connection(
        &self,
    ) -> Result<bb8::PooledConnection<'_, crate::pool::ImapConnectionManager>, McpError> {
        self.provider
            .imap_pool()
            .get()
            .await
            .map_err(|e| McpError::internal_error(e.to_string(), None))
    }

    /// A DEDICATED IMAP connection: it does not go through the pool and is
    /// NEVER returned to it — on drop it is simply closed. Used for the
    /// draft APPEND, which can leave the session waiting for a literal (a
    /// non-reusable protocol state).
    async fn dedicated_imap_session(&self) -> Result<crate::pool::TlsImapSession, McpError> {
        let auth = match self.config.imap_auth {
            crate::config::AuthMechanism::Plain | crate::config::AuthMechanism::Auto => {
                crate::pool::AuthMethod::Plain {
                    password: self.config.imap_password.clone(),
                }
            }
            crate::config::AuthMechanism::Login => crate::pool::AuthMethod::Login {
                password: self.config.imap_password.clone(),
            },
            crate::config::AuthMechanism::XOAuth2 => {
                let token =
                    self.config.imap_xoauth2_token.clone().ok_or_else(|| {
                        McpError::internal_error("IMAP_XOAUTH2_TOKEN required", None)
                    })?;
                crate::pool::AuthMethod::XOAuth2 {
                    user: self.config.imap_user.clone(),
                    access_token: token,
                }
            }
            crate::config::AuthMechanism::CramMd5 => crate::pool::AuthMethod::CramMd5 {
                password: self.config.imap_password.clone(),
            },
        };
        let manager = crate::pool::ImapConnectionManager::new(
            self.config.imap_host.clone(),
            self.config.imap_port,
            self.config.imap_user.clone(),
            auth,
            self.config.imap_tls_reject_unauthorized,
            std::time::Duration::from_secs(self.config.operation_timeout_secs),
        );
        use bb8::ManageConnection as _;
        // The TLS handshake and the login have no internal timeout in the
        // manager (pool.rs only bounds the TCP connect): a peer that accepts
        // and then goes silent would hang without a limit. An outer deadline
        // with the same truthful message as the other branches.
        tokio::time::timeout(
            std::time::Duration::from_secs(self.config.operation_timeout_secs),
            manager.connect(),
        )
        .await
        .map_err(|_| {
            McpError::internal_error(
                "draft APPEND abandoned: the dedicated connection timed out during TLS handshake or login; nothing was transferred and the old draft is intact; the connection was discarded",
                None,
            )
        })?
        .map_err(|e| {
            McpError::internal_error(
                format!("dedicated connection for the draft APPEND failed (old draft intact): {e}"),
                None,
            )
        })
    }

    /// Get or lazily create the cached SMTP transport
    async fn get_smtp_transport(
        &self,
    ) -> Result<&lettre::AsyncSmtpTransport<lettre::Tokio1Executor>, McpError> {
        self.smtp_transport
            .get_or_try_init(|| async { self.build_smtp_transport() })
            .await
            .map_err(|e: EmailError| McpError::internal_error(e.to_string(), None))
    }

    /// Force-rebuild the SMTP transport after a transient failure.
    /// Note: `OnceCell` doesn't support reset, so the second call to `set`
    /// is a no-op if already initialized — this means retry reuses the same
    /// transport. For true reset we'd need a `RwLock<Option<_>>`, but lettre
    /// builds a fresh connection pool per `send()` call anyway, so rebuilding
    /// only matters if credentials/host change at runtime (they don't).
    async fn rebuild_smtp_transport(&self) -> Result<(), McpError> {
        let new = self
            .build_smtp_transport()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let _ = self.smtp_transport.set(new);
        Ok(())
    }

    fn build_smtp_transport(
        &self,
    ) -> Result<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>, EmailError> {
        let host = self.provider.smtp_host();
        let port = self.provider.smtp_port();
        let user = self.provider.smtp_user();
        let pass = self.provider.smtp_password();

        let creds =
            lettre::transport::smtp::authentication::Credentials::new(user.to_string(), pass);

        let transport = if self.provider.smtp_starttls() {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::starttls_relay(host)
                .map_err(|e| EmailError::Smtp(format!("SMTP config error: {e}")))?
                .port(port)
                .credentials(creds)
                .build()
        } else {
            lettre::AsyncSmtpTransport::<lettre::Tokio1Executor>::relay(host)
                .map_err(|e| EmailError::Smtp(format!("SMTP config error: {e}")))?
                .port(port)
                .credentials(creds)
                .build()
        };

        Ok(transport)
    }

    /// Find a special folder (Drafts, Sent, Trash) by listing all folders once
    async fn find_special_folder<F>(
        &self,
        conn: &mut crate::pool::TlsImapSession,
        finder: F,
    ) -> Option<String>
    where
        F: Fn(&[FolderInfo]) -> Option<String>,
    {
        let folders = conn.list(Some(""), Some("*")).await.ok()?;
        let folders_vec: Vec<_> = folders.try_collect().await.ok()?;
        let folder_list: Vec<FolderInfo> = folders_vec
            .into_iter()
            .map(FolderInfo::from_imap_name)
            .collect();
        finder(&folder_list)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for EmailServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
    }
}

/// Controlled description of an SMTP send failure: severity and numeric
/// reply code only (`smtp transient 450`, `smtp permanent 550`, ...).
///
/// The raw server text is deliberately dropped: an SMTP refusal often
/// quotes the recipient address it is refusing — and a Bcc recipient is
/// envelope-only, so its address must never surface in a client error or
/// a log line. Public so the confidentiality tests exercise the exact
/// function used by the send path.
pub fn classify_smtp_send_failure(e: &lettre::transport::smtp::Error) -> String {
    let severity = if e.is_transient() {
        "transient"
    } else if e.is_permanent() {
        "permanent"
    } else {
        return if e.is_timeout() {
            "smtp timeout"
        } else if e.is_tls() {
            "smtp tls error"
        } else if e.is_transport_shutdown() {
            "smtp transport shutdown"
        } else if e.is_response() {
            "smtp response error"
        } else if e.is_client() {
            "smtp client error"
        } else {
            "smtp connection error"
        }
        .to_string();
    };
    match e.status() {
        Some(code) => format!("smtp {severity} {code}"),
        None => format!("smtp {severity}"),
    }
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::config::AuthMechanism;
    use serde_json::Value;
    use std::collections::BTreeSet;

    fn test_config() -> EmailConfig {
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
            smtp_save_sent: crate::config::SaveSentMode::Always,
            smtp_allowed_from: vec!["agent@example.test".into()],
            pool_max_connections: 1,
            pool_idle_timeout_secs: 30,
            operation_timeout_secs: 30,
            attachment_dir: None,
            attachment_max_mime_bytes: crate::attachments::DEFAULT_MAX_MIME_BYTES,
            attachment_max_count: crate::attachments::DEFAULT_MAX_COUNT,
        }
    }

    fn assert_portable_schema(value: &Value, path: &str) {
        match value {
            Value::Bool(true) => panic!("boolean true schema at {path}"),
            Value::Bool(false) | Value::Null | Value::Number(_) | Value::String(_) => {}
            Value::Array(values) => {
                for (index, item) in values.iter().enumerate() {
                    assert_portable_schema(item, &format!("{path}[{index}]"));
                }
            }
            Value::Object(map) => {
                assert!(
                    !map.contains_key("$defs"),
                    "schema uses $defs at {path}; keep MCP tool schemas inline for broad client compatibility"
                );
                if let Some(format) = map.get("format").and_then(Value::as_str) {
                    assert!(
                        !format.starts_with("uint"),
                        "schema uses non-portable unsigned integer format {format} at {path}"
                    );
                }
                for (key, item) in map {
                    assert_portable_schema(item, &format!("{path}.{key}"));
                }
            }
        }
    }

    #[tokio::test]
    async fn tools_list_schemas_are_portable() {
        let server = EmailServer::from_config(test_config()).expect("server should construct");
        let tools = server.tool_router.list_all();

        assert!(!tools.is_empty(), "server must expose tools");
        for tool in &tools {
            assert!(!tool.name.trim().is_empty(), "tool name is required");
            assert!(
                tool.description
                    .as_ref()
                    .map(|description| !description.trim().is_empty())
                    .unwrap_or(false),
                "{} must have a non-empty description",
                tool.name
            );

            let schema = Value::Object((*tool.input_schema).clone());
            assert_eq!(
                schema.get("type").and_then(Value::as_str),
                Some("object"),
                "{} inputSchema must be a JSON object schema: {schema}",
                tool.name
            );
            assert!(
                schema.get("properties").is_some_and(Value::is_object),
                "{} inputSchema must include properties, even when empty: {schema}",
                tool.name
            );
            assert_portable_schema(&schema, &format!("{}.inputSchema", tool.name));
        }
    }

    #[tokio::test]
    async fn all_expected_email_tools_stay_available() {
        let server = EmailServer::from_config(test_config()).expect("server should construct");
        let names: BTreeSet<_> = server
            .tool_router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();

        for required in [
            "list_folders",
            "create_folder",
            "delete_folder",
            "rename_folder",
            "get_quota",
            "list_namespaces",
            "list_emails",
            "get_email",
            "get_email_raw",
            "get_bodystructure",
            "search_emails",
            "send_email",
            "list_drafts",
            "create_draft",
            "update_draft",
            "delete_email",
            "move_email",
            "copy_email",
            "flag_email",
            "mark_seen",
            "batch_mark_seen",
            "batch_delete",
            "download_attachment",
            "move_thread",
            "idle_wait",
            "list_emails_with_headers",
            "list_recent_unseen",
        ] {
            assert!(names.contains(required), "missing email tool {required}");
        }
    }

    #[tokio::test]
    async fn download_attachment_schema_exposes_optional_save_path() {
        let server = EmailServer::from_config(test_config()).expect("server should construct");
        let tool = server
            .tool_router
            .list_all()
            .into_iter()
            .find(|tool| tool.name == "download_attachment")
            .expect("download_attachment tool should exist");

        let schema = Value::Object((*tool.input_schema).clone());
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("download_attachment properties should be an object");
        assert!(properties.contains_key("save_path"));

        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .expect("download_attachment required should be an array");
        assert!(required.iter().any(|value| value.as_str() == Some("uid")));
        assert!(
            required
                .iter()
                .any(|value| value.as_str() == Some("part_id"))
        );
        assert!(
            !required
                .iter()
                .any(|value| value.as_str() == Some("save_path"))
        );
    }

    #[test]
    fn validate_from_override_no_override_ok() {
        let allowed: Vec<String> = vec!["a@x.com".into()];
        assert!(EmailServer::validate_from_override(None, "a@x.com", &allowed).is_ok());
    }

    #[test]
    fn validate_from_override_default_implicit_ok() {
        let allowed: Vec<String> = vec![];
        assert!(
            EmailServer::validate_from_override(Some("default@x.com"), "default@x.com", &allowed)
                .is_ok()
        );
    }

    #[test]
    fn validate_from_override_listed_ok() {
        let allowed: Vec<String> = vec!["alias@x.com".into(), "other@x.com".into()];
        assert!(
            EmailServer::validate_from_override(Some("other@x.com"), "default@x.com", &allowed)
                .is_ok()
        );
    }

    #[test]
    fn validate_from_override_rejected_when_not_listed() {
        let allowed: Vec<String> = vec!["alias@x.com".into()];
        let err = EmailServer::validate_from_override(
            Some("spoofed@evil.com"),
            "default@x.com",
            &allowed,
        )
        .expect_err("must reject unlisted from");
        let msg = format!("{err}");
        assert!(
            msg.contains("not in smtp.allowed_from"),
            "error message should mention allowed_from; got: {msg}"
        );
    }

    #[tokio::test]
    async fn attachment_params_exposed_in_tool_schemas() {
        let server = EmailServer::from_config(test_config()).expect("server should construct");
        for name in ["send_email", "create_draft", "update_draft"] {
            let tool = server
                .tool_router
                .list_all()
                .into_iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("{name} tool must exist"));
            let schema = Value::Object((*tool.input_schema).clone());
            let properties = schema
                .get("properties")
                .and_then(Value::as_object)
                .unwrap_or_else(|| panic!("{name} schema must have properties"));
            assert!(
                properties.contains_key("attachments"),
                "{name} must expose `attachments`: {schema}"
            );
            // Inline schema: no $defs allowed (portability contract).
            assert!(
                !schema.to_string().contains("$defs"),
                "{name} schema must inline the attachment shape: {schema}"
            );
        }
    }

    #[tokio::test]
    async fn send_email_schema_exposes_from_param() {
        let server = EmailServer::from_config(test_config()).expect("server constructs");
        let tools = server.tool_router.list_all();
        let send = tools
            .iter()
            .find(|t| t.name == "send_email")
            .expect("send_email tool present");
        let schema = Value::Object((*send.input_schema).clone());
        let props = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("send_email schema must have properties");
        assert!(
            props.contains_key("from"),
            "send_email must expose `from` as optional override"
        );
    }

    #[test]
    fn normalize_imap_date_accepts_iso_and_imap_forms() {
        assert_eq!(
            normalize_imap_date("2026-08-30").unwrap(),
            "30-Aug-2026".to_string()
        );
        assert_eq!(
            normalize_imap_date("30-Aug-2026").unwrap(),
            "30-Aug-2026".to_string()
        );
        // month name case-insensitive, normalized to title case
        assert_eq!(
            normalize_imap_date("1-aug-2026").unwrap(),
            "01-Aug-2026".to_string()
        );
        // leap-year February 29 is accepted and normalized
        assert_eq!(
            normalize_imap_date("2024-02-29").unwrap(),
            "29-Feb-2024".to_string()
        );
        // ...while 29 February on a non-leap year is rejected
        assert!(normalize_imap_date("2026-02-29").is_err());
    }

    #[test]
    fn normalize_imap_date_rejects_with_named_formats() {
        for bad in [
            "30/08/2026", // the other reasonable-but-wrong guess
            "2026-13-01", // month out of range
            "2026-02-30", // day out of range for February
            "2026-08",    // incomplete
            "yesterday",  // free text
            "",           // empty
        ] {
            let err = normalize_imap_date(bad).unwrap_err();
            let message = err.message.clone();
            assert!(
                message.contains("YYYY-MM-DD") && message.contains("dd-Mon-yyyy"),
                "date error must name both accepted formats, got: {message}"
            );
        }
    }

    #[test]
    fn flag_is_seen_matches_both_renderings() {
        assert!(flag_is_seen("Seen"));
        assert!(flag_is_seen("\\Seen"));
        assert!(!flag_is_seen("Unseen"));
        assert!(!flag_is_seen("Recent"));
        assert!(!flag_is_seen("Flagged"));
        assert!(!flag_is_seen(""));
    }
}
