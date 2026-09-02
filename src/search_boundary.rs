//! The single send site for IMAP UID SEARCH commands.
//!
//! Some IMAP backends answer a criteria string ending in a bare space
//! with an empty untagged SEARCH and no error; async-imap swallows the
//! tagged BAD (its response filter matches the tag only, parse.rs
//! `filter_sync`), so a filtered query reports "[]" as if the mailbox
//! were legitimately empty. Composers append `"KEY "` fragments, so a
//! stray trailing space is easy to reintroduce. The defense is
//! structural, not conventional: [`uid_search`] here is the only
//! function in the crate allowed to call `.uid_search(` on a session,
//! and [`boundary_tests::uid_search_is_only_called_from_the_boundary_module`]
//! fails if any other library source file calls it directly.
//!
//! The boundary also owns the shape contract of a search program. We
//! only ever send single-line programs this crate composed, so the
//! boundary REFUSES CR/LF and IMAP raw-literal syntax instead of
//! passing them through, and strips at most the trailing ASCII space
//! separator our own composers append — no other whitespace is
//! touched, and a quoted literal such as `SUBJECT "foo "` keeps its
//! inner space because stripping stops at the last non-space byte of
//! the program, which is the closing quote.
//!
use crate::pool::TlsImapSession;
use async_imap::Session;
use async_imap::error::Error;
use async_imap::imap_proto::{MailboxDatum, Response};
use async_imap::types::UnsolicitedResponse;
use rmcp::ErrorData as McpError;
use std::borrow::Cow;
use std::collections::HashSet;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};

/// Validate the shape of an IMAP search program and strip at most the
/// trailing ASCII space separator appended by this crate's composers.
///
/// Refuses: CR or LF anywhere (only single-line programs are sent),
/// raw-literal syntax (`{N}`), empty programs, and programs ending in
/// whitespace other than the ASCII space (which would mean the program
/// was not composed here). Never touches spaces inside the program.
pub(crate) fn sanitize_search_program(raw: &str) -> Result<Cow<'_, str>, McpError> {
    if raw.contains('\r') || raw.contains('\n') {
        return Err(McpError::internal_error(
            "search program contains CR/LF: only single-line search programs composed by this server are accepted",
            None,
        ));
    }
    if let Some(start) = raw.find('{') {
        let rest = &raw[start + 1..];
        if let Some(end) = rest.find('}')
            && end > 0
            && rest[..end].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(McpError::internal_error(
                "search program contains IMAP raw-literal syntax: not supported by the search boundary",
                None,
            ));
        }
    }
    let trimmed = raw.trim_end_matches(' ');
    if trimmed.is_empty() {
        return Err(McpError::internal_error("empty search program", None));
    }
    if let Some(last) = trimmed.chars().last()
        && last.is_whitespace()
    {
        return Err(McpError::internal_error(
            "search program ends in whitespace other than the ASCII space separator",
            None,
        ));
    }
    if trimmed.len() == raw.len() {
        Ok(Cow::Borrowed(raw))
    } else {
        Ok(Cow::Owned(trimmed.to_string()))
    }
}

/// The only place in this crate where `uid_search` reaches an IMAP
/// session. See the module documentation.
pub(crate) async fn uid_search(
    conn: &mut TlsImapSession,
    criteria: &str,
    timeout: Duration,
) -> Result<HashSet<u32>, McpError> {
    let program = sanitize_search_program(criteria)?;
    uid_search_failclosed(conn, program.as_ref(), timeout)
        .await
        .map_err(|e| McpError::internal_error(format!("IMAP SEARCH failed: {e}"), None))
}

/// Execute UID SEARCH while preserving the tagged server status.
///
/// async-imap's `uid_search` parser can turn BAD/NO into an empty success;
/// `run_command_and_check_ok` validates the tagged Done response and leaves
/// untagged SEARCH data in `unsolicited_responses`, which is collected here.
pub(crate) async fn uid_search_failclosed<T>(
    session: &mut Session<T>,
    criteria: &str,
    timeout: Duration,
) -> Result<HashSet<u32>, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + std::fmt::Debug,
{
    tokio::time::timeout(
        timeout,
        session.run_command_and_check_ok(format!("UID SEARCH {criteria}")),
    )
    .await
    .map_err(|_| Error::Io(std::io::Error::other("UID SEARCH: timeout")))??;

    let mut uids = HashSet::new();
    while let Ok(item) = session.unsolicited_responses.try_recv() {
        if let UnsolicitedResponse::Other(response_data) = &item
            && let Response::MailboxData(MailboxDatum::Search(ids)) = response_data.parsed()
        {
            uids.extend(ids.iter().copied());
        }
    }
    Ok(uids)
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    fn strip_comments(source: &str) -> String {
        let mut out = String::with_capacity(source.len());
        let mut chars = source.chars().peekable();
        let mut in_string = false;
        let mut in_char = false;
        let mut escaped = false;
        while let Some(ch) = chars.next() {
            if in_string {
                out.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            if in_char {
                out.push(ch);
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '\'' {
                    in_char = false;
                }
                continue;
            }
            if ch == '"' {
                in_string = true;
                out.push(ch);
            } else if ch == '\'' {
                in_char = true;
                out.push(ch);
            } else if ch == '/' && chars.peek() == Some(&'/') {
                chars.next();
                for next in chars.by_ref() {
                    if next == '\n' {
                        out.push('\n');
                        break;
                    }
                }
            } else if ch == '/' && chars.peek() == Some(&'*') {
                chars.next();
                let mut previous = '\0';
                for next in chars.by_ref() {
                    if previous == '*' && next == '/' {
                        break;
                    }
                    if next == '\n' {
                        out.push('\n');
                    }
                    previous = next;
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    fn bypass_lines(source: &str) -> Vec<String> {
        strip_comments(source)
            .lines()
            .filter(|line| {
                let direct_uid_search = line.contains(".uid_search(")
                    || (line.contains("::uid_search(")
                        && !line.contains("search_boundary::uid_search("));
                direct_uid_search || line.contains("uid_search_failclosed(")
            })
            .map(str::trim)
            .map(ToOwned::to_owned)
            .collect()
    }

    /// The structural guard: if any library file outside this module
    /// calls `.uid_search(` on a session, the boundary is bypassable
    /// and this test fails. It scans the sources instead of trusting
    /// a checklist.
    #[test]
    fn uid_search_is_only_called_from_the_boundary_module() {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let src_dir = std::path::Path::new(manifest).join("src");
        let mut entries = vec![src_dir.clone()];
        let mut offenders = Vec::new();
        while let Some(dir) = entries.pop() {
            for entry in std::fs::read_dir(&dir).expect("src directory is readable") {
                let path = entry.expect("src entry readable").path();
                if path.is_dir() {
                    entries.push(path);
                    continue;
                }
                if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some("search_boundary.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("source file readable");
                for line in bypass_lines(&text) {
                    offenders.push(format!("{}: {}", path.display(), line));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "uid_search called outside the search boundary module:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn bypass_guard_ignores_comments_but_detects_calls() {
        assert!(bypass_lines("// Session::uid_search(\n").is_empty());
        assert_eq!(
            bypass_lines("async_imap::Session::uid_search(\"ALL\");\n"),
            vec!["async_imap::Session::uid_search(\"ALL\");"]
        );
        assert_eq!(
            bypass_lines("conn.uid_search(\"ALL\");\n"),
            vec!["conn.uid_search(\"ALL\");"]
        );
        assert_eq!(
            bypass_lines("search_boundary::uid_search_failclosed(&mut conn, \"ALL\", timeout);\n"),
            vec!["search_boundary::uid_search_failclosed(&mut conn, \"ALL\", timeout);"]
        );
        assert!(
            bypass_lines("search_boundary::uid_search(&mut conn, \"ALL\", timeout);\n").is_empty()
        );
    }

    #[test]
    fn trailing_ascii_space_is_stripped_and_quoted_inner_space_survives() {
        assert_eq!(sanitize_search_program("UNSEEN").unwrap(), "UNSEEN");
        assert_eq!(sanitize_search_program("UNSEEN ").unwrap(), "UNSEEN");
        assert_eq!(
            sanitize_search_program("SINCE 1-Aug-2026  ").unwrap(),
            "SINCE 1-Aug-2026"
        );
        // The control the trim must not break: the space lives inside
        // the quoted literal, and the program ends with a quote.
        assert_eq!(
            sanitize_search_program("SUBJECT \"foo \"").unwrap(),
            "SUBJECT \"foo \""
        );
        assert_eq!(
            sanitize_search_program("SUBJECT foo ").unwrap(),
            "SUBJECT foo"
        );
        assert_eq!(sanitize_search_program("ALL").unwrap(), "ALL");
    }

    #[test]
    fn cr_lf_raw_literals_and_other_trailing_whitespace_are_refused() {
        assert!(sanitize_search_program("SUBJECT foo\r\nX").is_err());
        assert!(sanitize_search_program("SUBJECT foo\n").is_err());
        assert!(sanitize_search_program("SUBJECT {3}\r\nabc").is_err());
        assert!(sanitize_search_program("SUBJECT {3}").is_err());
        assert!(sanitize_search_program("UNSEEN\t").is_err());
        assert!(sanitize_search_program("").is_err());
        assert!(sanitize_search_program("   ").is_err());
    }

    #[test]
    fn quoted_raw_literals_are_refused() {
        assert!(sanitize_search_program(r#"SUBJECT "foo {3}""#).is_err());
    }

    const TIMEOUT: Duration = Duration::from_millis(800);

    #[derive(Clone, Copy)]
    enum SearchReply {
        Bad,
        No,
        WithResults,
        Hang,
        Close,
    }

    async fn spawn_fake_imap(reply: SearchReply) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                serve(sock, reply).await;
            }
        });
        addr
    }

    async fn serve(sock: TcpStream, reply: SearchReply) {
        let (read_half, mut write_half) = sock.into_split();
        let mut lines = BufReader::new(read_half).lines();
        let _ = write_half.write_all(b"* OK IMAP4rev1 fake ready\r\n").await;
        while let Ok(Some(line)) = lines.next_line().await {
            let mut tokens = line.split_whitespace();
            let tag = tokens.next().unwrap_or("*").to_string();
            let cmd = tokens.next().unwrap_or("").to_uppercase();
            let out = match cmd.as_str() {
                "LOGIN" => format!("{tag} OK LOGGED IN\r\n"),
                "SELECT" => {
                    "* 3 EXISTS\r\n".to_string() + &format!("{tag} OK [READ-WRITE] SELECT\r\n")
                }
                "NOOP" => format!("{tag} OK NOOP\r\n"),
                "UID" => match reply {
                    SearchReply::Bad => format!("{tag} BAD Could not parse search criteria\r\n"),
                    SearchReply::No => format!("{tag} NO Mailbox is unavailable\r\n"),
                    SearchReply::WithResults => {
                        "* SEARCH 1 2 3\r\n".to_string() + &format!("{tag} OK SEARCH DONE\r\n")
                    }
                    SearchReply::Hang => {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        return;
                    }
                    SearchReply::Close => return,
                },
                "LOGOUT" => {
                    let _ = write_half
                        .write_all(format!("{tag} OK BYE\r\n").as_bytes())
                        .await;
                    return;
                }
                _ => format!("{tag} OK\r\n"),
            };
            if write_half.write_all(out.as_bytes()).await.is_err() {
                return;
            }
        }
    }

    async fn session_on(addr: std::net::SocketAddr) -> Session<TcpStream> {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let client = async_imap::Client::new(tcp);
        client
            .login("user", "pass")
            .await
            .map_err(|(e, _)| e)
            .unwrap()
    }

    #[tokio::test]
    async fn il_server_risponde_bad_e_la_ricerca_deve_fallire() {
        let addr = spawn_fake_imap(SearchReply::Bad).await;
        let mut session = session_on(addr).await;
        let res = uid_search_failclosed(&mut session, "ALL", TIMEOUT).await;
        let err = res.expect_err("un BAD del server non è «nessuna email»: deve essere un errore");
        assert!(
            err.to_string().to_lowercase().contains("bad"),
            "errore atteso BAD, letto: {err}"
        );
    }

    #[tokio::test]
    async fn il_server_risponde_no_e_la_ricerca_deve_fallire() {
        let addr = spawn_fake_imap(SearchReply::No).await;
        let mut session = session_on(addr).await;
        let res = uid_search_failclosed(&mut session, "ALL", TIMEOUT).await;
        let err = res.expect_err("un NO del server non è «nessuna email»: deve essere un errore");
        assert!(
            err.to_string().to_lowercase().contains("no response"),
            "errore atteso NO, letto: {err}"
        );
    }

    #[tokio::test]
    async fn il_server_non_risponde_e_la_ricerca_deve_fallire_per_timeout() {
        let addr = spawn_fake_imap(SearchReply::Hang).await;
        let mut session = session_on(addr).await;
        let res = uid_search_failclosed(&mut session, "ALL", TIMEOUT).await;
        let err = res.expect_err("un server muto deve produrre un errore, non una lista vuota");
        assert!(
            err.to_string().to_lowercase().contains("timeout"),
            "errore atteso timeout, letto: {err}"
        );
    }

    #[tokio::test]
    async fn la_connessione_chiusa_a_meta_risposta_deve_fallire() {
        let addr = spawn_fake_imap(SearchReply::Close).await;
        let mut session = session_on(addr).await;
        let res = uid_search_failclosed(&mut session, "ALL", TIMEOUT).await;
        assert!(
            res.is_err(),
            "chiusura a metà risposta: errore atteso, non lista vuota"
        );
    }

    #[tokio::test]
    async fn server_sano_la_ricerca_restituisce_gli_uid() {
        let addr = spawn_fake_imap(SearchReply::WithResults).await;
        let mut session = session_on(addr).await;
        let uids = uid_search_failclosed(&mut session, "ALL", TIMEOUT)
            .await
            .expect("con un server sano la ricerca deve funzionare");
        assert_eq!(uids, [1u32, 2, 3].into_iter().collect());
    }
}
