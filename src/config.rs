use std::path::Path;

use crate::error::EmailError;

/// IMAP authentication mechanism
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMechanism {
    /// Standard PLAIN over TLS (default)
    Plain,
    /// Legacy LOGIN command
    Login,
    /// XOAUTH2 SASL — user supplies access token directly
    XOAuth2,
    /// CRAM-MD5 challenge-response
    CramMd5,
    /// Accepted for forward-compat; currently resolved to PLAIN (no capability negotiation).
    Auto,
}

impl AuthMechanism {
    // Inherent fallible parser kept as the public API; not the std FromStr trait.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, EmailError> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(Self::Plain),
            "login" => Ok(Self::Login),
            "xoauth2" => Ok(Self::XOAuth2),
            "cram-md5" | "crammd5" => Ok(Self::CramMd5),
            "auto" => Ok(Self::Auto),
            other => Err(EmailError::Config(format!(
                "Unknown IMAP_AUTH: {other}. Use: plain, login, xoauth2, cram-md5, auto"
            ))),
        }
    }
}

/// Whether the client should APPEND a copy of sent mail to the IMAP Sent folder.
///
/// Gmail, Outlook, and Office 365 auto-save into Sent after authenticated SMTP
/// submission. APPENDing on top of that produces duplicates. The resolved mode
/// is computed once at config load time so the server-side code stays simple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveSentMode {
    /// Client appends sent mail explicitly via IMAP.
    Always,
    /// Server auto-saves; client skips APPEND.
    Never,
}

impl SaveSentMode {
    /// Resolve final mode given user preference (toml, env) and smtp host.
    ///
    /// Precedence: env override > toml setting > auto-detect by host.
    /// Recognised string values: "true"/"always" → Always, "false"/"never" → Never,
    /// "auto"/missing → detection.
    pub fn resolve(toml_val: Option<&str>, env_val: Option<&str>, smtp_host: &str) -> Self {
        let pick = env_val.or(toml_val).map(|v| v.to_lowercase());
        match pick.as_deref() {
            Some("true") | Some("always") => SaveSentMode::Always,
            Some("false") | Some("never") => SaveSentMode::Never,
            _ => Self::detect(smtp_host),
        }
    }

    /// Auto-detect based on SMTP host.
    pub fn detect(smtp_host: &str) -> Self {
        let h = smtp_host.to_lowercase();
        if h.contains("gmail") || h.contains("outlook") || h.contains("office365") {
            SaveSentMode::Never
        } else {
            SaveSentMode::Always
        }
    }
}

/// TOML config file structure (serde deserializable)
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
struct TomlConfig {
    imap: TomlImap,
    smtp: TomlSmtp,
    pool: TomlPool,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
#[derive(Default)]
struct TomlImap {
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    tls: Option<bool>,
    tls_reject_unauthorized: Option<bool>,
    auth: Option<String>,
    xoauth2_token: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
#[derive(Default)]
struct TomlSmtp {
    host: Option<String>,
    port: Option<u16>,
    user: Option<String>,
    password: Option<String>,
    starttls: Option<bool>,
    from_address: Option<String>,
    save_sent: Option<String>,
    allowed_from: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
#[derive(Default)]
struct TomlPool {
    max_connections: Option<usize>,
    idle_timeout_secs: Option<u64>,
    operation_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct EmailConfig {
    // IMAP
    pub imap_host: String,
    pub imap_port: u16,
    pub imap_user: String,
    pub imap_password: String,
    pub imap_tls: bool,
    pub imap_tls_reject_unauthorized: bool,
    pub imap_auth: AuthMechanism,

    // XOAUTH2 access token (only used when imap_auth = XOAuth2)
    pub imap_xoauth2_token: Option<String>,

    // SMTP
    pub smtp_host: String,
    pub smtp_port: u16,
    pub smtp_user: String,
    pub smtp_password: String,
    pub smtp_starttls: bool,
    /// Default From address used when send_email is invoked without `from` override.
    /// Falls back to `imap_user` when neither config file nor env var sets it.
    pub smtp_from_address: String,
    /// Whether the client should APPEND outgoing mail to the IMAP Sent folder.
    /// Auto-detected from `smtp_host` (Gmail/Outlook → Never, else Always)
    /// unless overridden via `smtp.save_sent` config or `EMAIL_SAVE_SENT` env.
    pub smtp_save_sent: SaveSentMode,
    /// Addresses allowed as From override on send_email. Defaults to
    /// `[smtp_from_address]` so the tool cannot spoof unrelated addresses.
    pub smtp_allowed_from: Vec<String>,

    // Pool
    pub pool_max_connections: usize,
    pub pool_idle_timeout_secs: u64,

    // Operation timeout (seconds)
    pub operation_timeout_secs: u64,
}

impl EmailConfig {
    /// Load config from TOML file (if present), then env vars as fallback.
    /// Searches for config file at:
    /// 1. `EMAIL_CONFIG` env var path
    /// 2. `./email.toml`
    /// 3. `~/.config/mcp-email-rs/email.toml`
    pub fn load() -> Result<Self, EmailError> {
        let toml = Self::load_toml()?;
        Self::build_from(toml)
    }

    /// Load from env vars only (no TOML file)
    pub fn from_env() -> Result<Self, EmailError> {
        Self::build_from(None)
    }

    /// Resolve the TOML config path the binary would read, in the same order
    /// as [`Self::load_toml`]. Returns `None` if no candidate exists. The
    /// `EMAIL_CONFIG` env path is returned as-is even when the file is
    /// missing, mirroring the load behaviour (the subsequent read will error
    /// explicitly instead of silently falling back).
    pub fn resolve_toml_path() -> Option<std::path::PathBuf> {
        if let Ok(path) = std::env::var("EMAIL_CONFIG") {
            return Some(Path::new(&path).to_path_buf());
        }
        if Path::new("email.toml").exists() {
            return Some(Path::new("email.toml").to_path_buf());
        }
        if let Ok(home) = std::env::var("HOME") {
            let p = Path::new(&home).join(".config/mcp-email-rs/email.toml");
            if p.exists() {
                return Some(p);
            }
        }
        None
    }

    fn load_toml() -> Result<Option<TomlConfig>, EmailError> {
        let config_path = Self::resolve_toml_path();

        match config_path {
            Some(path) => {
                let content = std::fs::read_to_string(&path).map_err(|e| {
                    EmailError::Config(format!("Failed to read {}: {e}", path.display()))
                })?;
                let config: TomlConfig = toml::from_str(&content).map_err(|e| {
                    EmailError::Config(format!("Failed to parse {}: {e}", path.display()))
                })?;
                tracing::info!("Loaded config from {}", path.display());
                Ok(Some(config))
            }
            None => Ok(None),
        }
    }

    fn build_from(toml: Option<TomlConfig>) -> Result<Self, EmailError> {
        let t = toml.unwrap_or_default();
        let ti = &t.imap;
        let ts = &t.smtp;
        let tp = &t.pool;

        let imap_host = ti
            .host
            .clone()
            .or_else(|| std::env::var("IMAP_HOST").ok())
            .ok_or_else(|| {
                EmailError::Config("IMAP_HOST is required (env or config file)".into())
            })?;

        let imap_port: u16 = ti
            .port
            .or_else(|| std::env::var("IMAP_PORT").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(993);

        let imap_user = ti
            .user
            .clone()
            .or_else(|| std::env::var("IMAP_USER").ok())
            .ok_or_else(|| {
                EmailError::Config("IMAP_USER is required (env or config file)".into())
            })?;

        let imap_password = ti
            .password
            .clone()
            .or_else(|| std::env::var("IMAP_PASSWORD").ok())
            .ok_or_else(|| {
                EmailError::Config("IMAP_PASSWORD is required (env or config file)".into())
            })?;

        let imap_tls = ti
            .tls
            .or_else(|| std::env::var("IMAP_TLS").ok().map(|v| v != "false"))
            .unwrap_or(true);

        let imap_tls_reject_unauthorized = ti
            .tls_reject_unauthorized
            .or_else(|| {
                std::env::var("IMAP_TLS_REJECT_UNAUTHORIZED")
                    .ok()
                    .map(|v| v != "false")
            })
            .unwrap_or(true);

        let imap_auth_env = std::env::var("IMAP_AUTH").ok();
        let imap_auth = ti
            .auth
            .as_deref()
            .or(imap_auth_env.as_deref())
            .map(AuthMechanism::from_str)
            .transpose()?
            .unwrap_or(AuthMechanism::Plain);

        let imap_xoauth2_token = ti
            .xoauth2_token
            .clone()
            .or_else(|| std::env::var("IMAP_XOAUTH2_TOKEN").ok());

        let smtp_host = ts
            .host
            .clone()
            .or_else(|| std::env::var("SMTP_HOST").ok())
            .unwrap_or_else(|| imap_host.clone());

        let smtp_port: u16 = ts
            .port
            .or_else(|| std::env::var("SMTP_PORT").ok().and_then(|v| v.parse().ok()))
            .unwrap_or(465);

        let smtp_user = ts
            .user
            .clone()
            .or_else(|| std::env::var("SMTP_USER").ok())
            .unwrap_or_else(|| imap_user.clone());

        let smtp_password = ts
            .password
            .clone()
            .or_else(|| std::env::var("SMTP_PASSWORD").ok())
            .unwrap_or_else(|| imap_password.clone());

        let smtp_starttls = ts
            .starttls
            .or_else(|| std::env::var("SMTP_STARTTLS").ok().map(|v| v == "true"))
            .unwrap_or(false);

        let smtp_from_address = ts
            .from_address
            .clone()
            .or_else(|| std::env::var("SMTP_FROM_ADDRESS").ok())
            .unwrap_or_else(|| imap_user.clone());

        let save_sent_env = std::env::var("EMAIL_SAVE_SENT").ok();
        let smtp_save_sent = SaveSentMode::resolve(
            ts.save_sent.as_deref(),
            save_sent_env.as_deref(),
            &smtp_host,
        );

        let smtp_allowed_from = ts
            .allowed_from
            .clone()
            .unwrap_or_else(|| vec![smtp_from_address.clone()]);

        let pool_max_connections = tp
            .max_connections
            .or_else(|| {
                std::env::var("EMAIL_POOL_MAX_CONNECTIONS")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(4);

        let pool_idle_timeout_secs = tp
            .idle_timeout_secs
            .or_else(|| {
                std::env::var("EMAIL_POOL_IDLE_TIMEOUT")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(300);

        let operation_timeout_secs = tp
            .operation_timeout_secs
            .or_else(|| {
                std::env::var("EMAIL_OPERATION_TIMEOUT")
                    .ok()
                    .and_then(|v| v.parse().ok())
            })
            .unwrap_or(30);

        Ok(Self {
            imap_host,
            imap_port,
            imap_user,
            imap_password,
            imap_tls,
            imap_tls_reject_unauthorized,
            imap_auth,
            imap_xoauth2_token,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_password,
            smtp_starttls,
            smtp_from_address,
            smtp_save_sent,
            smtp_allowed_from,
            pool_max_connections,
            pool_idle_timeout_secs,
            operation_timeout_secs,
        })
    }

    /// Test-only helper to build EmailConfig from a TOML string. Bypasses env vars.
    #[cfg(test)]
    pub(crate) fn from_toml_str(s: &str) -> Result<Self, EmailError> {
        let toml: TomlConfig = toml::from_str(s).map_err(|e| EmailError::Config(e.to_string()))?;
        // Save env vars that could pollute the build; clear them temporarily.
        let snapshot: Vec<(&str, Option<String>)> = [
            "IMAP_HOST",
            "IMAP_PORT",
            "IMAP_USER",
            "IMAP_PASSWORD",
            "SMTP_HOST",
            "SMTP_PORT",
            "SMTP_USER",
            "SMTP_PASSWORD",
            "SMTP_FROM_ADDRESS",
            "EMAIL_SAVE_SENT",
        ]
        .iter()
        .map(|k| (*k, std::env::var(k).ok()))
        .collect();
        for (k, _) in &snapshot {
            // SAFETY: tests run single-threaded per process via cargo's harness.
            unsafe { std::env::remove_var(k) };
        }
        let result = Self::build_from(Some(toml));
        for (k, v) in snapshot {
            unsafe {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
        result
    }

    /// Validate config consistency
    pub fn validate(&self) -> Result<(), EmailError> {
        if self.imap_host.is_empty() {
            return Err(EmailError::Config("IMAP_HOST cannot be empty".into()));
        }
        if self.imap_user.is_empty() {
            return Err(EmailError::Config("IMAP_USER cannot be empty".into()));
        }
        if self.imap_password.is_empty() && self.imap_auth != AuthMechanism::XOAuth2 {
            return Err(EmailError::Config(
                "IMAP_PASSWORD is required for non-XOAuth2 auth".into(),
            ));
        }
        if self.imap_auth == AuthMechanism::XOAuth2 && self.imap_xoauth2_token.is_none() {
            return Err(EmailError::Config(
                "IMAP_XOAUTH2_TOKEN is required when IMAP_AUTH=xoauth2".into(),
            ));
        }
        if self.pool_max_connections == 0 {
            return Err(EmailError::Config(
                "EMAIL_POOL_MAX_CONNECTIONS must be > 0".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_sent_detect_gmail_outlook_office365() {
        assert_eq!(SaveSentMode::detect("smtp.gmail.com"), SaveSentMode::Never);
        assert_eq!(
            SaveSentMode::detect("smtp-mail.outlook.com"),
            SaveSentMode::Never
        );
        assert_eq!(
            SaveSentMode::detect("smtp.office365.com"),
            SaveSentMode::Never
        );
    }

    #[test]
    fn save_sent_detect_generic() {
        assert_eq!(
            SaveSentMode::detect("mail.example.com"),
            SaveSentMode::Always
        );
        assert_eq!(
            SaveSentMode::detect("smtp.fastmail.com"),
            SaveSentMode::Always
        );
    }

    #[test]
    fn save_sent_resolve_explicit_overrides_detection() {
        // Generic host but user forces Never
        assert_eq!(
            SaveSentMode::resolve(Some("false"), None, "mail.example.com"),
            SaveSentMode::Never
        );
        // Gmail but user forces Always
        assert_eq!(
            SaveSentMode::resolve(Some("true"), None, "smtp.gmail.com"),
            SaveSentMode::Always
        );
        // Env overrides toml
        assert_eq!(
            SaveSentMode::resolve(Some("true"), Some("false"), "mail.example.com"),
            SaveSentMode::Never
        );
        // Auto falls back to detection
        assert_eq!(
            SaveSentMode::resolve(Some("auto"), None, "smtp.gmail.com"),
            SaveSentMode::Never
        );
    }

    #[test]
    fn from_address_falls_back_to_imap_user() {
        let toml = r#"
            [imap]
            host = "imap.example.com"
            user = "agent@example.com"
            password = "pw"

            [smtp]
            host = "smtp.example.com"
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_from_address, "agent@example.com");
        assert_eq!(cfg.smtp_allowed_from, vec!["agent@example.com".to_string()]);
    }

    #[test]
    fn from_address_explicit_and_allowed_from_default() {
        let toml = r#"
            [imap]
            host = "imap.example.com"
            user = "agent@example.com"
            password = "pw"

            [smtp]
            host = "smtp.example.com"
            from_address = "alias@example.com"
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_from_address, "alias@example.com");
        // Default allowed_from contains only the configured from_address
        assert_eq!(cfg.smtp_allowed_from, vec!["alias@example.com".to_string()]);
    }

    #[test]
    fn allowed_from_explicit_list_preserved() {
        let toml = r#"
            [imap]
            host = "imap.example.com"
            user = "agent@example.com"
            password = "pw"

            [smtp]
            host = "smtp.example.com"
            from_address = "alias@example.com"
            allowed_from = ["alias@example.com", "second@example.com", "third@example.com"]
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_allowed_from.len(), 3);
        assert!(
            cfg.smtp_allowed_from
                .contains(&"second@example.com".to_string())
        );
    }

    #[test]
    fn smtp_save_sent_resolves_gmail_to_never() {
        let toml = r#"
            [imap]
            host = "imap.gmail.com"
            user = "user@gmail.com"
            password = "pw"

            [smtp]
            host = "smtp.gmail.com"
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_save_sent, SaveSentMode::Never);
    }

    #[test]
    fn smtp_save_sent_resolves_generic_to_always() {
        let toml = r#"
            [imap]
            host = "imap.example.com"
            user = "user@example.com"
            password = "pw"

            [smtp]
            host = "smtp.example.com"
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_save_sent, SaveSentMode::Always);
    }

    #[test]
    fn smtp_save_sent_explicit_false_overrides_generic() {
        let toml = r#"
            [imap]
            host = "imap.example.com"
            user = "user@example.com"
            password = "pw"

            [smtp]
            host = "smtp.example.com"
            save_sent = "false"
        "#;
        let cfg = EmailConfig::from_toml_str(toml).expect("config builds");
        assert_eq!(cfg.smtp_save_sent, SaveSentMode::Never);
    }
}
