use mail_parser::MimeHeaders;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct EmailAddress {
    pub name: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailSummary {
    pub uid: u32,
    pub subject: Option<String>,
    pub from: Option<String>,
    pub to: Option<Vec<String>>,
    pub date: Option<String>,
    pub flags: Vec<String>,
    pub size: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmailDetail {
    pub uid: u32,
    pub subject: Option<String>,
    pub from: Option<EmailAddress>,
    pub to: Option<Vec<EmailAddress>>,
    pub cc: Option<Vec<EmailAddress>>,
    pub bcc: Option<Vec<EmailAddress>>,
    pub date: Option<String>,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttachmentInfo {
    pub part_id: String,
    pub filename: Option<String>,
    pub content_type: String,
    pub size: usize,
}

/// Parse a raw email message into an EmailDetail
pub fn parse_email(
    uid: u32,
    raw: &[u8],
    flags: Vec<String>,
) -> Result<EmailDetail, crate::error::EmailError> {
    let message = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| crate::error::EmailError::MimeParse("Failed to parse email".into()))?;

    let from = message.from().and_then(|addr| {
        let first = addr.first()?;
        Some(EmailAddress {
            name: first.name.clone().map(|s| s.to_string()),
            address: first.address.clone()?.to_string(),
        })
    });

    let to = message.to().map(|addrs| {
        addrs
            .iter()
            .filter_map(|a| {
                Some(EmailAddress {
                    name: a.name.clone().map(|s| s.to_string()),
                    address: a.address.clone()?.to_string(),
                })
            })
            .collect::<Vec<_>>()
    });

    let cc = message.cc().map(|addrs| {
        addrs
            .iter()
            .filter_map(|a| {
                Some(EmailAddress {
                    name: a.name.clone().map(|s| s.to_string()),
                    address: a.address.clone()?.to_string(),
                })
            })
            .collect::<Vec<_>>()
    });

    let bcc = message.bcc().map(|addrs| {
        addrs
            .iter()
            .filter_map(|a| {
                Some(EmailAddress {
                    name: a.name.clone().map(|s| s.to_string()),
                    address: a.address.clone()?.to_string(),
                })
            })
            .collect::<Vec<_>>()
    });

    let subject = message.subject().map(|s| s.to_string());
    let date = message.date().map(|d| d.to_rfc3339());

    let text_body = message.body_text(0).map(|t| t.to_string());
    let html_body = message.body_html(0).map(|h| h.to_string());

    let attachments = extract_attachments(&message);

    Ok(EmailDetail {
        uid,
        subject,
        from,
        to,
        cc,
        bcc,
        date,
        text_body,
        html_body,
        attachments,
        flags,
    })
}

/// Extract a decoded attachment payload by the 1-based attachment id exposed in AttachmentInfo.
pub fn extract_attachment_bytes(
    raw: &[u8],
    part_id: &str,
) -> Result<Vec<u8>, crate::error::EmailError> {
    let index = part_id
        .parse::<usize>()
        .ok()
        .and_then(|value| value.checked_sub(1))
        .ok_or_else(|| crate::error::EmailError::AttachmentNotFound {
            part_id: part_id.to_string(),
        })?;

    let message = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| crate::error::EmailError::MimeParse("Failed to parse email".into()))?;

    let part = message.attachment(index as u32).ok_or_else(|| {
        crate::error::EmailError::AttachmentNotFound {
            part_id: part_id.to_string(),
        }
    })?;

    Ok(part.contents().to_vec())
}

/// Extract attachment info from a parsed email using mail-parser 0.11 API.
/// Uses `message.attachments()` iterator and `message.attachment(pos)` accessor.
fn extract_attachments(message: &mail_parser::Message<'_>) -> Vec<AttachmentInfo> {
    let mut result = Vec::new();
    let count = message.attachment_count();

    for i in 0..count {
        if let Some(part) = message.attachment(i as u32) {
            let filename = part.attachment_name().map(|n| n.to_string());

            let content_type = part
                .content_type()
                .map(|ct: &mail_parser::ContentType<'_>| {
                    let base = ct.c_type.as_ref();
                    match &ct.c_subtype {
                        Some(sub) => format!("{}/{}", base, sub),
                        None => base.to_string(),
                    }
                })
                .unwrap_or_else(|| "application/octet-stream".to_string());

            let size = match &part.body {
                mail_parser::PartType::Binary(data) => data.len(),
                mail_parser::PartType::InlineBinary(data) => data.len(),
                mail_parser::PartType::Text(text) => text.len(),
                mail_parser::PartType::Html(html) => html.len(),
                _ => 0,
            };

            result.push(AttachmentInfo {
                part_id: format!("{}", i + 1),
                filename,
                content_type,
                size,
            });
        }
    }

    result
}

/// Extract envelope summary from IMAP FETCH response
pub fn extract_summary(uid: u32, fetch: &async_imap::types::Fetch) -> EmailSummary {
    let subject = fetch
        .envelope()
        .and_then(|env| env.subject.clone())
        .map(|s| String::from_utf8_lossy(&s).to_string());

    let from = fetch
        .envelope()
        .and_then(|env| env.from.as_ref())
        .map(|addrs| {
            addrs
                .first()
                .map(|a| {
                    let name = a
                        .name
                        .as_ref()
                        .map(|n| String::from_utf8_lossy(n).to_string());
                    let addr = a
                        .mailbox
                        .as_ref()
                        .map(|m| String::from_utf8_lossy(m).to_string())
                        .unwrap_or_default();
                    let host = a
                        .host
                        .as_ref()
                        .map(|h| String::from_utf8_lossy(h).to_string())
                        .unwrap_or_default();
                    match name {
                        Some(n) if !n.is_empty() => format!("{n} <{addr}@{host}>"),
                        _ => format!("{addr}@{host}"),
                    }
                })
                .unwrap_or_default()
        });

    let to = fetch
        .envelope()
        .and_then(|env| env.to.as_ref())
        .map(|addrs| {
            addrs
                .iter()
                .map(|a| {
                    let addr = a
                        .mailbox
                        .as_ref()
                        .map(|m| String::from_utf8_lossy(m).to_string())
                        .unwrap_or_default();
                    let host = a
                        .host
                        .as_ref()
                        .map(|h| String::from_utf8_lossy(h).to_string())
                        .unwrap_or_default();
                    format!("{addr}@{host}")
                })
                .collect::<Vec<_>>()
        });

    let date = fetch
        .envelope()
        .and_then(|env| env.date.clone())
        .map(|d| String::from_utf8_lossy(&d).to_string());

    let flags: Vec<String> = fetch.flags().map(|f| format!("{f:?}")).collect();

    EmailSummary {
        uid,
        subject,
        from,
        to,
        date,
        flags,
        size: fetch.size,
    }
}
