use std::fs;

fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("tests/fixtures/{name}");
    fs::read(&path).unwrap_or_else(|e| panic!("Failed to read fixture {path}: {e}"))
}

#[test]
fn parse_basic_email() {
    let raw = read_fixture("sample.eml");
    let detail = mcp_email_rs::message::parse_email(42, &raw, vec!["\\Seen".to_string()])
        .expect("parse failed");

    assert_eq!(detail.uid, 42);
    assert_eq!(
        detail.subject.as_deref(),
        Some("Test Email with Attachment è una prova")
    );
    assert!(detail.from.is_some());
    let from = detail.from.as_ref().unwrap();
    assert_eq!(from.address, "alice@example.com");

    assert!(detail.to.is_some());
    let to = detail.to.as_ref().unwrap();
    assert_eq!(to.len(), 1);
    assert_eq!(to[0].address, "bob@example.com");

    assert!(detail.cc.is_some());
    let cc = detail.cc.as_ref().unwrap();
    assert_eq!(cc.len(), 1);
    assert_eq!(cc[0].address, "charlie@example.com");

    assert!(detail.text_body.is_some());
    assert!(
        detail
            .text_body
            .as_ref()
            .unwrap()
            .contains("test email body")
    );

    // HTML body may or may not be parsed depending on MIME structure
    // At minimum, text body should contain the content
    let has_body = detail.text_body.is_some() || detail.html_body.is_some();
    assert!(has_body, "Should have at least a text or HTML body");

    // Should detect the PDF attachment
    assert!(
        !detail.attachments.is_empty(),
        "Should have at least one attachment"
    );
    let att = &detail.attachments[0];
    assert_eq!(att.filename.as_deref(), Some("report.pdf"));
    assert!(att.content_type.contains("pdf"));
    assert!(att.size > 0);

    assert!(detail.flags.contains(&"\\Seen".to_string()));
}

#[test]
fn normalize_thread_subject_strips_re() {
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("Re: Hello"),
        "Hello"
    );
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("RE: Hello"),
        "Hello"
    );
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("Re: Re: Hello"),
        "Hello"
    );
}

#[test]
fn normalize_thread_subject_strips_fwd() {
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("Fwd: Hello"),
        "Hello"
    );
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("FW: Hello"),
        "Hello"
    );
}

#[test]
fn normalize_thread_subject_passthrough() {
    assert_eq!(
        mcp_email_rs::folder::normalize_thread_subject("Hello World"),
        "Hello World"
    );
}

#[test]
fn parse_simple_email_no_attachments() {
    let raw = read_fixture("simple.eml");
    let detail = mcp_email_rs::message::parse_email(1, &raw, vec![]).expect("parse failed");

    assert_eq!(detail.uid, 1);
    assert_eq!(detail.subject.as_deref(), Some("Simple plain text email"));
    assert!(detail.from.is_some());
    assert!(detail.text_body.is_some());
    assert!(
        detail
            .text_body
            .as_ref()
            .unwrap()
            .contains("simple plain text email")
    );
    assert!(detail.attachments.is_empty());
    assert!(detail.flags.is_empty());
}

#[test]
fn extract_attachment_bytes_uses_parser_attachment_index() {
    let raw = read_fixture("sample.eml");
    let data =
        mcp_email_rs::message::extract_attachment_bytes(&raw, "1").expect("attachment extract");

    assert!(!data.is_empty());
    assert!(data.starts_with(b"%PDF"));
}

#[test]
fn extract_attachment_bytes_rejects_invalid_part_id() {
    let raw = read_fixture("sample.eml");

    assert!(mcp_email_rs::message::extract_attachment_bytes(&raw, "0").is_err());
    assert!(mcp_email_rs::message::extract_attachment_bytes(&raw, "abc").is_err());
    assert!(mcp_email_rs::message::extract_attachment_bytes(&raw, "99").is_err());
}

#[test]
fn folder_find_drafts() {
    use mcp_email_rs::folder::{FolderInfo, find_drafts_folder};
    let folders = vec![
        FolderInfo {
            name: "INBOX".into(),
            delimiter: ".".into(),
            flags: vec![],
        },
        FolderInfo {
            name: "[Gmail]/Drafts".into(),
            delimiter: "/".into(),
            flags: vec![],
        },
    ];
    assert_eq!(
        find_drafts_folder(&folders),
        Some("[Gmail]/Drafts".to_string())
    );
    assert_eq!(find_drafts_folder(&[]), None);
}

#[test]
fn folder_find_sent() {
    use mcp_email_rs::folder::{FolderInfo, find_sent_folder};
    let folders = vec![
        FolderInfo {
            name: "INBOX".into(),
            delimiter: ".".into(),
            flags: vec![],
        },
        FolderInfo {
            name: "[Gmail]/Sent Mail".into(),
            delimiter: "/".into(),
            flags: vec![],
        },
    ];
    assert_eq!(
        find_sent_folder(&folders),
        Some("[Gmail]/Sent Mail".to_string())
    );
}

#[test]
fn folder_find_trash() {
    use mcp_email_rs::folder::{FolderInfo, find_trash_folder};
    let folders = vec![
        FolderInfo {
            name: "INBOX".into(),
            delimiter: ".".into(),
            flags: vec![],
        },
        FolderInfo {
            name: "[Gmail]/Trash".into(),
            delimiter: "/".into(),
            flags: vec![],
        },
    ];
    assert_eq!(
        find_trash_folder(&folders),
        Some("[Gmail]/Trash".to_string())
    );
}

#[test]
fn folder_find_drafts_italian() {
    use mcp_email_rs::folder::{FolderInfo, find_drafts_folder};
    let folders = vec![FolderInfo {
        name: "[Gmail]/Bozze".into(),
        delimiter: "/".into(),
        flags: vec![],
    }];
    assert_eq!(
        find_drafts_folder(&folders),
        Some("[Gmail]/Bozze".to_string())
    );
}

#[test]
fn error_kind_classification() {
    use mcp_email_rs::error::EmailError;
    // Transient
    assert!(EmailError::Timeout("test".into()).is_transient());
    assert!(EmailError::Pool("conn lost".into()).is_transient());
    assert!(EmailError::Smtp("connection refused".into()).is_transient());
    // Permanent
    assert!(!EmailError::Config("bad".into()).is_transient());
    assert!(!EmailError::AuthFailed("denied".into()).is_transient());
    assert!(!EmailError::FolderNotFound("x".into()).is_transient());
    assert!(
        !EmailError::EmailNotFound {
            uid: 1,
            folder: "INBOX".into()
        }
        .is_transient()
    );
}

mod config_tests {
    use mcp_email_rs::config::{AuthMechanism, EmailConfig};

    #[test]
    fn auth_mechanism_from_str() {
        assert_eq!(
            AuthMechanism::from_str("plain").unwrap(),
            AuthMechanism::Plain
        );
        assert_eq!(
            AuthMechanism::from_str("LOGIN").unwrap(),
            AuthMechanism::Login
        );
        assert_eq!(
            AuthMechanism::from_str("xoauth2").unwrap(),
            AuthMechanism::XOAuth2
        );
        assert_eq!(
            AuthMechanism::from_str("cram-md5").unwrap(),
            AuthMechanism::CramMd5
        );
        assert_eq!(
            AuthMechanism::from_str("auto").unwrap(),
            AuthMechanism::Auto
        );
        assert!(AuthMechanism::from_str("invalid").is_err());
    }

    #[test]
    fn config_validate_rejects_empty_host() {
        let config = EmailConfig {
            imap_host: String::new(),
            imap_port: 993,
            imap_user: "test@test.com".to_string(),
            imap_password: "pass".to_string(),
            imap_tls: true,
            imap_tls_reject_unauthorized: true,
            imap_auth: AuthMechanism::Plain,
            imap_xoauth2_token: None,
            smtp_host: "smtp.test.com".to_string(),
            smtp_port: 465,
            smtp_user: "test@test.com".to_string(),
            smtp_password: "pass".to_string(),
            smtp_starttls: false,
            smtp_from_address: "test@test.com".to_string(),
            smtp_save_sent: mcp_email_rs::config::SaveSentMode::Always,
            smtp_allowed_from: vec!["test@test.com".to_string()],
            pool_max_connections: 4,
            pool_idle_timeout_secs: 300,
            operation_timeout_secs: 30,
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validate_accepts_valid() {
        let config = EmailConfig {
            imap_host: "imap.test.com".to_string(),
            imap_port: 993,
            imap_user: "test@test.com".to_string(),
            imap_password: "pass".to_string(),
            imap_tls: true,
            imap_tls_reject_unauthorized: true,
            imap_auth: AuthMechanism::Plain,
            imap_xoauth2_token: None,
            smtp_host: "smtp.test.com".to_string(),
            smtp_port: 465,
            smtp_user: "test@test.com".to_string(),
            smtp_password: "pass".to_string(),
            smtp_starttls: false,
            smtp_from_address: "test@test.com".to_string(),
            smtp_save_sent: mcp_email_rs::config::SaveSentMode::Always,
            smtp_allowed_from: vec!["test@test.com".to_string()],
            pool_max_connections: 4,
            pool_idle_timeout_secs: 300,
            operation_timeout_secs: 30,
        };
        assert!(config.validate().is_ok());
    }
}
