use async_imap::Session;
use bb8::Pool;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::EmailConfig;
use crate::error::EmailError;

pub type TlsImapSession = Session<TlsStream<TcpStream>>;

/// IMAP authentication method
#[derive(Clone)]
pub enum AuthMethod {
    Plain { password: String },
    Login { password: String },
    XOAuth2 { user: String, access_token: String },
    CramMd5 { password: String },
}

fn build_tls_config(verify: bool) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    if !verify {
        // Danger: skip certificate verification (for self-signed servers)
        let mut dangerous = config;
        dangerous
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
        Arc::new(dangerous)
    } else {
        Arc::new(config)
    }
}

/// Certificate verifier that accepts everything (for self-signed IMAP servers)
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
        ]
    }
}

pub struct ImapConnectionManager {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth_method: AuthMethod,
    pub verify_tls: bool,
    pub operation_timeout: Duration,
}

impl ImapConnectionManager {
    pub fn new(
        host: String,
        port: u16,
        user: String,
        auth_method: AuthMethod,
        verify_tls: bool,
        operation_timeout: Duration,
    ) -> Self {
        Self {
            host,
            port,
            user,
            auth_method,
            verify_tls,
            operation_timeout,
        }
    }
}

impl bb8::ManageConnection for ImapConnectionManager {
    type Connection = TlsImapSession;
    type Error = EmailError;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let addr = format!("{}:{}", self.host, self.port);

        let stream = tokio::time::timeout(self.operation_timeout, TcpStream::connect(&addr))
            .await
            .map_err(|_| EmailError::Timeout(format!("IMAP connect timeout to {addr}")))??;

        let tls_config = build_tls_config(self.verify_tls);
        let tls = tokio_rustls::TlsConnector::from(tls_config);

        let domain: rustls::pki_types::ServerName<'static> =
            rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|e| EmailError::Config(format!("Invalid TLS domain: {e}")))?
                .to_owned();

        let tls_stream = tls.connect(domain, stream).await?;
        let client = async_imap::Client::new(tls_stream);

        // Authenticate based on the configured method
        let session = match &self.auth_method {
            AuthMethod::Plain { password } => client
                .login(&self.user, password)
                .await
                .map_err(|(e, _)| e)?,
            AuthMethod::Login { password } => {
                // Some servers require LOGIN instead of PLAIN
                // async-imap uses login() which sends LOGIN command
                client
                    .login(&self.user, password)
                    .await
                    .map_err(|(e, _)| e)?
            }
            AuthMethod::XOAuth2 { user, access_token } => {
                let auth = crate::provider::XOAuth2Authenticator {
                    user: user.clone(),
                    access_token: access_token.clone(),
                };
                client
                    .authenticate("XOAUTH2", auth)
                    .await
                    .map_err(|(e, _)| e)?
            }
            AuthMethod::CramMd5 { password } => {
                let auth = CramMd5Authenticator {
                    user: self.user.clone(),
                    password: password.clone(),
                };
                client
                    .authenticate("CRAM-MD5", auth)
                    .await
                    .map_err(|(e, _)| e)?
            }
        };

        Ok(session)
    }

    async fn is_valid(&self, conn: &mut Self::Connection) -> Result<(), Self::Error> {
        tokio::time::timeout(self.operation_timeout, conn.noop())
            .await
            .map_err(|_| EmailError::Timeout("IMAP NOOP timeout".into()))??;
        Ok(())
    }

    fn has_broken(&self, conn: &mut Self::Connection) -> bool {
        // Check if the TLS stream is still viable.
        // We cannot do async checks here, so we check if the session
        // can still be referenced. Real broken detection happens in is_valid().
        // This is called synchronously — return false and let is_valid() catch it.
        let _ = conn;
        false
    }
}

/// CRAM-MD5 authenticator
struct CramMd5Authenticator {
    user: String,
    password: String,
}

impl async_imap::Authenticator for CramMd5Authenticator {
    type Response = String;

    fn process(&mut self, data: &[u8]) -> Self::Response {
        use hmac::{Hmac, Mac};
        type HmacMd5 = Hmac<md5::Md5>;

        let mut mac = HmacMd5::new_from_slice(self.password.as_bytes())
            .expect("HMAC key length is always valid");
        mac.update(data);
        let result = mac.finalize().into_bytes();

        format!("{} {:032x}", self.user, result)
    }
}

/// Connection pool health metrics
#[derive(Debug, Clone)]
pub struct PoolMetrics {
    pub active_connections: u32,
    pub idle_connections: u32,
    pub max_size: u32,
    pub total_created: u64,
    pub total_recycled: u64,
    pub last_check: Instant,
}

pub struct ImapPool {
    pool: Pool<ImapConnectionManager>,
}

impl ImapPool {
    pub fn new(config: &EmailConfig, auth_method: AuthMethod) -> Self {
        let manager = ImapConnectionManager::new(
            config.imap_host.clone(),
            config.imap_port,
            config.imap_user.clone(),
            auth_method,
            config.imap_tls_reject_unauthorized,
            Duration::from_secs(config.operation_timeout_secs),
        );

        let pool = Pool::builder()
            .max_size(config.pool_max_connections as u32)
            .idle_timeout(Some(Duration::from_secs(config.pool_idle_timeout_secs)))
            .connection_timeout(Duration::from_secs(30))
            .max_lifetime(Some(Duration::from_secs(1800)))
            .build_unchecked(manager);

        Self { pool }
    }

    pub async fn get(
        &self,
    ) -> Result<bb8::PooledConnection<'_, ImapConnectionManager>, EmailError> {
        self.pool
            .get()
            .await
            .map_err(|e| EmailError::Pool(e.to_string()))
    }

    /// Get current pool state for diagnostics
    pub fn state(&self) -> bb8::State {
        self.pool.state()
    }
}
