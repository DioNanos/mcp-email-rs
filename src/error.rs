use thiserror::Error;

/// Whether an error is transient (retryable) or permanent
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ErrorKind {
    /// Transient — connection lost, timeout, server busy. Worth retrying.
    Transient,
    /// Permanent — auth failed, not found, invalid config. No point retrying.
    Permanent,
}

#[derive(Debug, Error)]
pub enum EmailError {
    #[error("IMAP error: {0}")]
    Imap(#[from] async_imap::error::Error),

    #[error("SMTP error: {0}")]
    Smtp(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Folder not found: {0}")]
    FolderNotFound(String),

    #[error("Email not found: uid={uid} in {folder}")]
    EmailNotFound { uid: u32, folder: String },

    #[error("Attachment not found: part_id={part_id}")]
    AttachmentNotFound { part_id: String },

    #[error("MIME parse error: {0}")]
    MimeParse(String),

    #[error("Connection pool error: {0}")]
    Pool(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Operation timeout: {0}")]
    Timeout(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("{0}")]
    Other(String),
}

impl EmailError {
    pub fn kind(&self) -> ErrorKind {
        match self {
            Self::Imap(e) => match e {
                async_imap::error::Error::Io(_) => ErrorKind::Transient,
                async_imap::error::Error::ConnectionLost => ErrorKind::Transient,
                _ => ErrorKind::Permanent,
            },
            Self::Smtp(_) => ErrorKind::Transient,
            Self::Pool(_) => ErrorKind::Transient,
            Self::Timeout(_) => ErrorKind::Transient,
            Self::AuthFailed(_) => ErrorKind::Permanent,
            Self::Config(_) => ErrorKind::Permanent,
            Self::FolderNotFound(_) => ErrorKind::Permanent,
            Self::EmailNotFound { .. } => ErrorKind::Permanent,
            Self::AttachmentNotFound { .. } => ErrorKind::Permanent,
            Self::MimeParse(_) => ErrorKind::Permanent,
            Self::Io(_) => ErrorKind::Transient,
            Self::Json(_) => ErrorKind::Permanent,
            Self::Other(_) => ErrorKind::Permanent,
        }
    }

    pub fn is_transient(&self) -> bool {
        self.kind() == ErrorKind::Transient
    }
}

impl From<lettre::transport::smtp::Error> for EmailError {
    fn from(e: lettre::transport::smtp::Error) -> Self {
        EmailError::Smtp(e.to_string())
    }
}

impl From<bb8::RunError<EmailError>> for EmailError {
    fn from(e: bb8::RunError<EmailError>) -> Self {
        EmailError::Pool(e.to_string())
    }
}
