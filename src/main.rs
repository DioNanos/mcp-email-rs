use anyhow::Result;
use mcp_email_rs::{config::EmailConfig, server::EmailServer};
use rmcp::ServiceExt;
use rustls::crypto::ring::default_provider;
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<()> {
    // Handle --version / --help short-circuit (before any MCP stdio / TLS / tracing setup)
    let args: Vec<String> = std::env::args().collect();
    if matches!(
        args.get(1).map(|s| s.as_str()),
        Some("--version") | Some("-V")
    ) {
        println!("mcp-email-rs {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    if matches!(args.get(1).map(|s| s.as_str()), Some("--help") | Some("-h")) {
        eprintln!("mcp-email-rs — MCP Email Server (IMAP + SMTP)");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  mcp-email-rs                  Start MCP server (stdio)");
        eprintln!("  mcp-email-rs --version | -V   Print version and exit");
        eprintln!("  mcp-email-rs --help    | -h   Print this help and exit");
        eprintln!();
        eprintln!("Config (TOML preferred; ENV fallback for IMAP/SMTP connection fields):");
        eprintln!(
            "  EMAIL_CONFIG       Path to email.toml (default: ~/.config/mcp-email-rs/email.toml)"
        );
        eprintln!("  EMAIL_AUDIT_LOG    Path to audit log sink (target `audit::*`)");
        eprintln!();
        eprintln!("Env IMAP/SMTP (fallback if TOML missing):");
        eprintln!(
            "  IMAP_HOST IMAP_PORT IMAP_USER IMAP_PASSWORD IMAP_AUTH IMAP_TLS IMAP_XOAUTH2_TOKEN IMAP_TLS_REJECT_UNAUTHORIZED"
        );
        eprintln!("  SMTP_HOST SMTP_PORT SMTP_USER SMTP_PASSWORD SMTP_STARTTLS SMTP_FROM_ADDRESS");
        eprintln!(
            "  EMAIL_PROVIDER EMAIL_POOL_MAX_CONNECTIONS EMAIL_POOL_IDLE_TIMEOUT EMAIL_OPERATION_TIMEOUT"
        );
        eprintln!("  EMAIL_SAVE_SENT    Overrides smtp.save_sent (env > toml > auto-detect)");
        return Ok(());
    }

    // Install ring as the default CryptoProvider before any TLS operations
    default_provider().install_default().ok();

    // Tracing setup
    //
    // - RUST_LOG controls stderr console output (default: silent — stderr noise
    //   breaks the MCP stdio transport).
    // - EMAIL_AUDIT_LOG=<path> appends structured audit events (target `audit::*`)
    //   to a dedicated file. The guard must live for the duration of the program
    //   to keep the non-blocking writer flushing.
    let registry = tracing_subscriber::registry();
    let console_layer = std::env::var("RUST_LOG")
        .ok()
        .map(|_| fmt::layer().with_filter(EnvFilter::from_default_env()));

    let mut _audit_guard: Option<tracing_appender::non_blocking::WorkerGuard> = None;
    let audit_layer = std::env::var("EMAIL_AUDIT_LOG").ok().and_then(|raw| {
        let path = std::path::PathBuf::from(&raw);
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let filename = path.file_name()?.to_owned();
        let file_appender = tracing_appender::rolling::never(dir, filename);
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
        _audit_guard = Some(guard);
        Some(
            fmt::layer()
                .with_ansi(false)
                .with_target(true)
                .with_writer(non_blocking)
                .with_filter(EnvFilter::new("audit=info")),
        )
    });

    registry.with(console_layer).with(audit_layer).init();

    dotenvy::dotenv().ok();

    let config = EmailConfig::load()?;
    config.validate()?;

    tracing::info!(
        "Starting mcp-email-rs v{} — IMAP {}:{} (auth: {:?})",
        env!("CARGO_PKG_VERSION"),
        config.imap_host,
        config.imap_port,
        config.imap_auth,
    );

    let server = EmailServer::from_config(config)?;

    let service = server
        .serve(rmcp::transport::io::stdio())
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {e}"))?;

    service.waiting().await?;
    Ok(())
}
