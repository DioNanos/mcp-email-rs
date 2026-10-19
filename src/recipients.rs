//! Recipient lists (`to`, `cc`, `bcc`) for outgoing mail.
//!
//! One parser for the three outgoing composers (`send_email`,
//! `create_draft`, `update_draft`). The grammar authority is lettre
//! 0.11.21 (`Mailboxes::from_str`, RFC 5322 mailbox-list, comma-only);
//! this module adds only:
//!
//! - a minimal adapter: `;` is accepted as a top-level separator exactly
//!   like `,` — never inside quoted strings (with `\` quoted-pairs) or
//!   inside comments (nested parentheses);
//! - explicit validation of the whole list: empty input, empty items and
//!   leading/trailing separators are rejected with the field name and the
//!   1-based index of the offending entry;
//! - CR, LF and NUL are rejected anywhere in the input, before any
//!   parsing side effect.
//!
//! Rejected outright, never reinterpreted: RFC 5322 address groups
//! (`Team: a@x, b@x;`), comments (lettre 0.11 has no comment support
//! either) and anything else lettre's parser refuses. Quoted local-parts
//! whose content is a valid bare local-part round-trip like today (lettre
//! serializes them without the quotes); quoted local-parts that NEED the
//! quotes were never accepted by lettre's `Address` validation and stay
//! rejected with an explicit entry error.
//!
//! Error hygiene: no error message contains the raw input or any address
//! (including Bcc addresses) — failures report only the field name, the
//! entry index and the reason.

use lettre::message::{Mailbox, Mailboxes};
use rmcp::ErrorData as McpError;

/// The three parsed recipient fields of an outgoing compose call.
#[derive(Debug, Default)]
pub(crate) struct RecipientLists {
    /// `to`: required, at least one mailbox.
    pub to: Vec<Mailbox>,
    /// `cc`: `None` when the parameter is omitted.
    pub cc: Option<Vec<Mailbox>>,
    /// `bcc`: `None` when the parameter is omitted.
    pub bcc: Option<Vec<Mailbox>>,
}

/// Parses the recipient fields of an outgoing message: `to` (required),
/// `cc` and `bcc` (optional; `Some` of an empty/blank/invalid list is an
/// error, `None` stays `None`).
///
/// The whole list is validated before returning: an invalid entry at any
/// index rejects the entire field, so callers fail before any side effect
/// (attachments, SMTP, APPEND, STORE, EXPUNGE).
pub(crate) fn parse_recipients(
    to: &str,
    cc: Option<&str>,
    bcc: Option<&str>,
) -> Result<RecipientLists, McpError> {
    Ok(RecipientLists {
        to: parse_mailbox_list("to", to)?,
        cc: parse_optional_mailbox_list("cc", cc)?,
        bcc: parse_optional_mailbox_list("bcc", bcc)?,
    })
}

/// Applies the parsed recipients to a builder as `To`/`Cc`/`Bcc` headers.
///
/// Header vs envelope is decided by the CALLER through the builder:
/// - send path: lettre's default `drop_bcc` removes the `Bcc` header at
///   build time, after `Envelope::try_from(&headers)` has collected
///   To+Cc+Bcc into the SMTP envelope (RFC 5322 §3.6.3);
/// - draft path: the caller sets `.keep_bcc()` so the private IMAP draft
///   keeps the `Bcc` header and stays editable.
pub(crate) fn apply_recipients(
    mut builder: lettre::message::MessageBuilder,
    lists: RecipientLists,
) -> lettre::message::MessageBuilder {
    for mbox in lists.to {
        builder = builder.to(mbox);
    }
    for mbox in lists.cc.into_iter().flatten() {
        builder = builder.cc(mbox);
    }
    for mbox in lists.bcc.into_iter().flatten() {
        builder = builder.bcc(mbox);
    }
    builder
}

/// Parses a required recipient list: at least one valid mailbox.
pub(crate) fn parse_mailbox_list(field: &str, raw: &str) -> Result<Vec<Mailbox>, McpError> {
    reject_control_chars(field, raw)?;
    if raw.trim().is_empty() {
        return Err(invalid(
            field,
            "entry 1 is empty: the recipient list must contain at least one address",
        ));
    }
    let entries = split_top_level(raw.trim());
    for (index, entry) in entries.iter().enumerate() {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(invalid(
                field,
                &format!(
                    "entry {} is empty: empty items and leading/trailing separators are rejected",
                    index + 1
                ),
            ));
        }
        if entry.parse::<Mailbox>().is_err() {
            return Err(invalid(
                field,
                &format!(
                    "entry {} is not a valid RFC 5322 mailbox (groups and comments are not supported)",
                    index + 1
                ),
            ));
        }
    }
    // Grammar authority over the whole list: lettre's RFC 5322
    // mailbox-list parser on the rebuilt comma-only form. Unreachable in
    // practice once every entry parses individually, kept as the final
    // arbiter so the list grammar never depends on the per-entry checks.
    let normalized = entries
        .iter()
        .map(|entry| entry.trim())
        .collect::<Vec<_>>()
        .join(",");
    let mailboxes: Mailboxes = normalized
        .parse()
        .map_err(|_| invalid(field, "not a valid RFC 5322 mailbox list"))?;
    Ok(mailboxes.into_iter().collect())
}

/// Parses an optional recipient list: `None` stays `None`, `Some(raw)` is
/// parsed with the same rules as the required field (so an empty or
/// whitespace-only `Some` is an error, not a silent skip).
pub(crate) fn parse_optional_mailbox_list(
    field: &str,
    raw: Option<&str>,
) -> Result<Option<Vec<Mailbox>>, McpError> {
    match raw {
        None => Ok(None),
        Some(raw) => Ok(Some(parse_mailbox_list(field, raw)?)),
    }
}

/// Number of top-level entries in a recipient list, for audit logging:
/// counts separators only outside quotes/comments. Never validated — on
/// the success path the list has already been parsed.
pub(crate) fn entry_count(raw: &str) -> usize {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        0
    } else {
        split_top_level(trimmed).len()
    }
}

/// CR, LF and NUL are rejected anywhere in a recipient list, before any
/// parsing: they have no business in a header value.
fn reject_control_chars(field: &str, raw: &str) -> Result<(), McpError> {
    if raw.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err(invalid(
            field,
            "CR, LF and NUL bytes are not allowed in a recipient list",
        ));
    }
    Ok(())
}

/// Splits `raw` at TOP-LEVEL `,` and `;`: separators inside quoted
/// strings (RFC 5322 quoted-string, with `\` quoted-pairs) and inside
/// comments (nested parentheses, again with quoted-pairs) are ordinary
/// text. Entries are returned verbatim, separators dropped.
///
/// Unterminated quotes or comments simply swallow the rest of the input
/// into the current entry, which then fails mailbox parsing with an
/// explicit error — never a reinterpretation.
fn split_top_level(raw: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_escape = false;
    let mut comment_depth: u32 = 0;
    let mut comment_escape = false;
    for ch in raw.chars() {
        if comment_depth > 0 {
            if comment_escape {
                comment_escape = false;
            } else if ch == '\\' {
                comment_escape = true;
            } else if ch == '(' {
                comment_depth += 1;
            } else if ch == ')' {
                comment_depth -= 1;
            }
            current.push(ch);
            continue;
        }
        if in_quotes {
            if quote_escape {
                quote_escape = false;
            } else if ch == '\\' {
                quote_escape = true;
            } else if ch == '"' {
                in_quotes = false;
            }
            current.push(ch);
            continue;
        }
        match ch {
            '"' => {
                in_quotes = true;
                current.push(ch);
            }
            '(' => {
                comment_depth += 1;
                current.push(ch);
            }
            ',' | ';' => entries.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    entries.push(current);
    entries
}

fn invalid(field: &str, detail: &str) -> McpError {
    McpError::internal_error(format!("Invalid {field}: {detail}"), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emails(field: &str, raw: &str) -> Result<Vec<String>, String> {
        parse_mailbox_list(field, raw)
            .map(|list| list.iter().map(|m| m.email.to_string()).collect())
            .map_err(|e| format!("{e:?}"))
    }

    // ── Single forms accepted before the list support (zero regression) ──

    #[test]
    fn single_bare_address() {
        assert_eq!(
            emails("to", "dest@example.test").unwrap(),
            vec!["dest@example.test"]
        );
    }

    #[test]
    fn single_with_surrounding_whitespace() {
        assert_eq!(
            emails("to", "  dest@example.test \t").unwrap(),
            vec!["dest@example.test"]
        );
    }

    #[test]
    fn single_display_name() {
        assert_eq!(
            emails("to", "Bob <bob@example.test>").unwrap(),
            vec!["bob@example.test"]
        );
    }

    #[test]
    fn single_quoted_display_name_with_comma() {
        assert_eq!(
            emails("to", "\"Doe, John\" <john@example.test>").unwrap(),
            vec!["john@example.test"]
        );
    }

    #[test]
    fn single_quoted_display_name_with_semicolon() {
        assert_eq!(
            emails("to", "\"Doe; John\" <john@example.test>").unwrap(),
            vec!["john@example.test"]
        );
    }

    #[test]
    fn single_quoted_display_name_with_escaped_quote() {
        assert_eq!(
            emails("to", "\"Doe \\\"JD\\\" John\" <john@example.test>").unwrap(),
            vec!["john@example.test"]
        );
    }

    #[test]
    fn single_quoted_local_part_with_benign_content() {
        // Quotes around content that is also a valid bare local part were
        // accepted before the list support and stay accepted; lettre
        // serializes the address without the (optional) quotes.
        assert_eq!(
            emails("to", "\"john.doe\"@example.test").unwrap(),
            vec!["john.doe@example.test"]
        );
    }

    // ── Lists: commas, semicolons, quoted separators ────────────────

    #[test]
    fn comma_separated_list() {
        assert_eq!(
            emails("to", "a@example.test,b@example.test").unwrap(),
            vec!["a@example.test", "b@example.test"]
        );
    }

    #[test]
    fn comma_separated_list_with_spaces() {
        assert_eq!(
            emails("to", "a@example.test, b@example.test").unwrap(),
            vec!["a@example.test", "b@example.test"]
        );
    }

    #[test]
    fn semicolon_separated_list() {
        assert_eq!(
            emails("to", "a@example.test;b@example.test").unwrap(),
            vec!["a@example.test", "b@example.test"]
        );
    }

    #[test]
    fn semicolon_separated_list_with_spaces() {
        assert_eq!(
            emails("to", "a@example.test ; b@example.test").unwrap(),
            vec!["a@example.test", "b@example.test"]
        );
    }

    #[test]
    fn mixed_separators_three_entries() {
        assert_eq!(
            emails("to", "a@example.test, b@example.test; c@example.test").unwrap(),
            vec!["a@example.test", "b@example.test", "c@example.test"]
        );
    }

    #[test]
    fn list_with_quoted_display_names_holding_separators() {
        let raw = "\"Doe, John\" <john@example.test>; \"Smith; Bob\" <bob@example.test>";
        assert_eq!(
            emails("to", raw).unwrap(),
            vec!["john@example.test", "bob@example.test"]
        );
    }

    #[test]
    fn scanner_never_splits_inside_quotes() {
        // Scanner mechanics only: separators inside quoted strings are
        // ordinary text (whether lettre later accepts the entry is a
        // separate question — see the doc comment on this module).
        assert_eq!(split_top_level("\"a;b\"@example.test").len(), 1);
        assert_eq!(split_top_level("\"Doe; John\" <a@example.test>").len(), 1);
        assert_eq!(split_top_level("\"Doe, John\" <a@example.test>").len(), 1);
        // And inside comments, even nested.
        assert_eq!(
            split_top_level("a@example.test (a;b), b@example.test").len(),
            2
        );
    }

    // ── Rejections: groups, empties, separators, control chars ───────

    #[test]
    fn rfc_group_is_rejected_whole() {
        for raw in [
            "Team: a@example.test;",
            "Team: a@example.test, b@example.test;",
            "undisclosed-recipients:;",
        ] {
            let err = emails("to", raw).unwrap_err();
            assert!(err.contains("Invalid to"), "field in error: {err}");
            assert!(
                !err.contains("example.test"),
                "no raw text or addresses in error: {err}"
            );
        }
    }

    #[test]
    fn empty_and_whitespace_only_lists_are_errors_with_index_one() {
        for raw in ["", "   ", "\t"] {
            let err = emails("cc", raw).unwrap_err();
            assert!(err.contains("Invalid cc"), "field in error: {err}");
            assert!(
                err.contains("entry 1"),
                "index 1 in error for the empty list: {err}"
            );
            assert!(err.contains("empty"), "reason in error: {err}");
        }
    }

    #[test]
    fn empty_list_reports_field_and_index_one_for_to_cc_and_bcc() {
        for field in ["to", "cc", "bcc"] {
            for raw in ["", " ", "\t", " \t "] {
                let err = emails(field, raw).unwrap_err();
                assert!(
                    err.contains(&format!("Invalid {field}")),
                    "field in error: {err}"
                );
                assert!(
                    err.contains("entry 1"),
                    "index 1 in error for {field}: {err}"
                );
                assert!(
                    !err.contains("example.test"),
                    "no raw text or addresses in error: {err}"
                );
            }
        }
    }

    #[test]
    fn trailing_separator_reports_index() {
        let err = emails("to", "a@example.test,").unwrap_err();
        assert!(err.contains("entry 2"), "index in error: {err}");
        assert!(err.contains("empty"), "reason in error: {err}");
    }

    #[test]
    fn leading_separator_reports_index() {
        let err = emails("to", ",a@example.test").unwrap_err();
        assert!(err.contains("entry 1"), "index in error: {err}");
    }

    #[test]
    fn empty_middle_entry_reports_index() {
        let err = emails("to", "a@example.test,,b@example.test").unwrap_err();
        assert!(err.contains("entry 2"), "index in error: {err}");
    }

    #[test]
    fn whitespace_only_entry_reports_index() {
        let err = emails("to", "a@example.test; ;b@example.test").unwrap_err();
        assert!(err.contains("entry 2"), "index in error: {err}");
    }

    #[test]
    fn invalid_entry_reports_its_index() {
        let err = emails("to", "a@example.test, non-e-una-email").unwrap_err();
        assert!(err.contains("entry 2"), "index in error: {err}");
        assert!(
            !err.contains("non-e-una-email"),
            "no raw text in error: {err}"
        );
    }

    #[test]
    fn invalid_entry_inside_cc_and_bcc_reports_the_field() {
        let err = emails("cc", "a@example.test; ???").unwrap_err();
        assert!(err.contains("Invalid cc"), "field in error: {err}");
        let err = emails("bcc", "a@example.test, -").unwrap_err();
        assert!(err.contains("Invalid bcc"), "field in error: {err}");
    }

    #[test]
    fn unterminated_quote_is_an_explicit_error() {
        let err = emails("to", "\"Doe, John <john@example.test>").unwrap_err();
        assert!(err.contains("Invalid to"), "field in error: {err}");
        assert!(
            !err.contains("john@example.test"),
            "no addresses in error: {err}"
        );
    }

    #[test]
    fn comment_is_not_silently_eaten() {
        // lettre 0.11 has no comment support: an entry carrying a comment
        // is rejected explicitly, never reinterpreted.
        let err = emails("to", "a@example.test (private)").unwrap_err();
        assert!(err.contains("Invalid to"), "field in error: {err}");
    }

    #[test]
    fn cr_lf_nul_are_rejected() {
        for raw in [
            "a@example.test\r\nb@example.test",
            "a@example.test\n",
            "a@example.test\r",
            "a\0@example.test",
            "a@example.test;b\0b@example.test",
        ] {
            let err = emails("to", raw).unwrap_err();
            assert!(err.contains("Invalid to"), "field in error: {err}");
            assert!(
                err.to_lowercase().contains("cr"),
                "control-char reason in error: {err}"
            );
        }
    }

    #[test]
    fn no_error_message_leaks_addresses() {
        for (field, raw) in [
            ("to", "a@example.test, b@example.test,,"),
            ("cc", "niente@"),
            ("bcc", "x"),
        ] {
            let err = parse_mailbox_list(field, raw)
                .map_err(|e| format!("{e:?}"))
                .unwrap_err();
            assert!(
                !err.contains("example.test") && !err.contains("niente") && !err.contains("x@"),
                "error must not echo raw input: {err}"
            );
        }
    }

    // ── Optional wrapper and audit counter ──────────────────────────

    #[test]
    fn optional_none_stays_none() {
        assert!(parse_optional_mailbox_list("cc", None).unwrap().is_none());
    }

    #[test]
    fn optional_some_is_parsed() {
        let list = parse_optional_mailbox_list("bcc", Some("a@example.test;b@example.test"))
            .unwrap()
            .expect("Some");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn optional_some_empty_is_an_error_with_index_one() {
        let err = parse_optional_mailbox_list("cc", Some("  "))
            .map_err(|e| format!("{e:?}"))
            .unwrap_err();
        assert!(err.contains("Invalid cc"), "field in error: {err}");
        assert!(
            err.contains("entry 1"),
            "index 1 in error for Some(\"\"): {err}"
        );
        assert!(
            parse_optional_mailbox_list("bcc", Some("\t"))
                .map_err(|e| format!("{e:?}"))
                .unwrap_err()
                .contains("entry 1"),
            "index 1 in error for Some(whitespace) bcc"
        );
    }

    #[test]
    fn entry_count_counts_top_level_only() {
        assert_eq!(entry_count(""), 0);
        assert_eq!(entry_count("   "), 0);
        assert_eq!(entry_count("a@example.test"), 1);
        assert_eq!(
            entry_count("a@example.test,b@example.test;c@example.test"),
            3
        );
        // Separators inside quotes are NOT separators.
        assert_eq!(entry_count("\"a,b;c\"@example.test"), 1);
    }
}
