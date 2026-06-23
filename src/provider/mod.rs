pub mod imap_provider;

use std::sync::Arc;

use async_trait::async_trait;

use crate::config::SaveSentMode;
use crate::pool::ImapPool;

/// XOAUTH2 authenticator for IMAP SASL
pub struct XOAuth2Authenticator {
    pub user: String,
    pub access_token: String,
}

impl async_imap::Authenticator for XOAuth2Authenticator {
    type Response = String;

    fn process(&mut self, _data: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

#[async_trait]
pub trait EmailProvider: Send + Sync + 'static {
    /// Get provider display name
    fn provider_name(&self) -> &str;

    /// Default From address for outgoing mail. Used when send_email is invoked
    /// without an explicit `from` parameter. Reflects `smtp_from_address` from
    /// the resolved EmailConfig (which falls back to imap_user when unset).
    fn default_from(&self) -> &str;

    /// Get SMTP user for sending
    fn smtp_user(&self) -> &str;

    /// Get SMTP password for sending
    fn smtp_password(&self) -> String;

    /// Whether SMTP uses STARTTLS
    fn smtp_starttls(&self) -> bool;

    /// Get SMTP host
    fn smtp_host(&self) -> &str;

    /// Get SMTP port
    fn smtp_port(&self) -> u16;

    /// Get IMAP connection pool
    fn imap_pool(&self) -> &Arc<ImapPool>;

    /// Resolved save-sent policy. Drives whether send_email APPENDs to the
    /// Sent IMAP folder explicitly or trusts server-side auto-save.
    fn save_sent_mode(&self) -> SaveSentMode;

    /// Addresses allowed as `from` override on send_email. Empty means no
    /// override is permitted (only the configured default is allowed).
    fn allowed_from(&self) -> &[String];
}
