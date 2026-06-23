use std::sync::Arc;

use async_trait::async_trait;

use super::EmailProvider;
use crate::config::{EmailConfig, SaveSentMode};
use crate::error::EmailError;
use crate::pool::{AuthMethod, ImapPool};

pub struct ImapProvider {
    config: EmailConfig,
    pool: Arc<ImapPool>,
}

impl ImapProvider {
    pub fn new(config: &EmailConfig) -> Result<Self, EmailError> {
        let auth = match config.imap_auth {
            crate::config::AuthMechanism::Plain | crate::config::AuthMechanism::Auto => {
                AuthMethod::Plain {
                    password: config.imap_password.clone(),
                }
            }
            crate::config::AuthMechanism::Login => AuthMethod::Login {
                password: config.imap_password.clone(),
            },
            crate::config::AuthMechanism::XOAuth2 => {
                let token = config
                    .imap_xoauth2_token
                    .clone()
                    .ok_or_else(|| EmailError::Config("IMAP_XOAUTH2_TOKEN required".into()))?;
                AuthMethod::XOAuth2 {
                    user: config.imap_user.clone(),
                    access_token: token,
                }
            }
            crate::config::AuthMechanism::CramMd5 => AuthMethod::CramMd5 {
                password: config.imap_password.clone(),
            },
        };

        let pool = Arc::new(ImapPool::new(config, auth));

        Ok(Self {
            config: config.clone(),
            pool,
        })
    }
}

#[async_trait]
impl EmailProvider for ImapProvider {
    fn provider_name(&self) -> &str {
        "IMAP"
    }

    fn default_from(&self) -> &str {
        &self.config.smtp_from_address
    }

    fn smtp_user(&self) -> &str {
        &self.config.smtp_user
    }

    fn smtp_password(&self) -> String {
        self.config.smtp_password.clone()
    }

    fn smtp_starttls(&self) -> bool {
        self.config.smtp_starttls
    }

    fn smtp_host(&self) -> &str {
        &self.config.smtp_host
    }

    fn smtp_port(&self) -> u16 {
        self.config.smtp_port
    }

    fn imap_pool(&self) -> &Arc<ImapPool> {
        &self.pool
    }

    fn save_sent_mode(&self) -> SaveSentMode {
        self.config.smtp_save_sent
    }

    fn allowed_from(&self) -> &[String] {
        &self.config.smtp_allowed_from
    }
}
