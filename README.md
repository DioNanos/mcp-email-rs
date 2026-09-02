# mcp-email-rs

[![CI](https://img.shields.io/github/actions/workflow/status/DioNanos/mcp-email-rs/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/DioNanos/mcp-email-rs/actions/workflows/ci.yml)
[![Tests](https://img.shields.io/badge/tests-32%20passing-2ea44f?style=flat-square)](https://github.com/DioNanos/mcp-email-rs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![MCP](https://img.shields.io/badge/MCP-stdio-111827?style=flat-square)](https://modelcontextprotocol.io)

Enterprise-grade MCP email server in pure Rust. Gives any MCP client
(Claude Code, Codex, or anything speaking MCP over stdio) full IMAP access and
SMTP sending — read, search, organize, draft, and send mail with your own
account, no third-party service in the middle.

The server talks IMAP/SMTP directly to your provider over TLS. Credentials stay
in your environment (or a local config file); they are never persisted or
logged by the server and never leave your machine except to your own mail
provider.

## Why

Agents that can read and send email are far more useful, but most integrations
route your mailbox through a vendor's cloud. This server keeps the connection
direct: your IMAP/SMTP host, your credentials, your machine. Swap the model or
the MCP client — the same mailbox tools are there, and nothing about your mail
is mediated by a platform.

Design choices that follow from that:

- **Direct IMAP/SMTP**: TLS connections straight to your provider (rustls); no
  proxy, no account on someone else's service.
- **Credentials from the environment**: read from env vars or a local
  `email.toml`/`.env`; both are git-ignored and never logged.
- **Pooled & resilient**: connection pooling (bb8), non-blocking pool creation,
  cached SMTP transport, folder-name resolution (incl. localized Gmail folders).
- **Auth options**: PLAIN, LOGIN, XOAUTH2 (caller-supplied token), CRAM-MD5.
- **Read-only by intent**: read/search tools are annotated `readOnlyHint`, so an
  MCP approval gate can auto-allow them while still gating mutations and sends.

> **The family:** for *curated agent state* (versioned JSON categories, fleet
> sync) see [mcp-memory-rs](https://github.com/DioNanos/mcp-memory-rs); for
> *corpus recall* (chunked documents, BM25 retrieval) see
> [mcp-vl-msa-rs](https://github.com/DioNanos/mcp-vl-msa-rs). This server adds
> the mailbox.

## Install

**Prebuilt binary** (recommended) — download the archive for your platform from
the [latest release](https://github.com/DioNanos/mcp-email-rs/releases/latest),
extract, and point your MCP client at the binary:

```bash
tar xzf mcp-email-rs-x86_64-unknown-linux-gnu.tar.gz
install -m755 mcp-email-rs-*/mcp-email-rs ~/.local/bin/
```

Prebuilt targets (Linux + Android): `x86_64-unknown-linux-gnu`,
`x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`,
`aarch64-unknown-linux-musl` (edge / ARM / Termux), `aarch64-linux-android`.

**macOS**: no prebuilt binary is shipped (it would need Apple code-signing).
Install from source instead:

```bash
cargo install --git https://github.com/DioNanos/mcp-email-rs --locked
```

`--locked` uses the committed `Cargo.lock` (reproducible build).

## Quick start

```bash
cargo build --release
./target/release/mcp-email-rs   # stdio MCP server
```

Claude Code (`~/.claude.json`) or any MCP client:

```json
{
  "mcpServers": {
    "email": {
      "command": "/path/to/mcp-email-rs",
      "env": {
        "IMAP_HOST": "imap.example.com",
        "IMAP_USER": "you@example.com",
        "IMAP_PASSWORD": "your-app-password"
      }
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.email]
command = "/path/to/mcp-email-rs"
env = { IMAP_HOST = "imap.example.com", IMAP_USER = "you@example.com", IMAP_PASSWORD = "..." }
# auto-approve read-only tools (list/get/search/…); mutations and sends still gated
default_tools_approval_mode = "approve"
```

## Configuration

Credentials are read from environment variables (or a local `email.toml`).
Copy `.env.example` to `.env` and fill in your values:

```bash
IMAP_HOST=imap.example.com
IMAP_PORT=993
IMAP_USER=you@example.com
IMAP_PASSWORD=your-app-password
IMAP_TLS=true
IMAP_AUTH=plain            # plain | login | xoauth2 | cram-md5

# SMTP is optional — defaults to the IMAP host/credentials
# SMTP_HOST=smtp.example.com
# SMTP_PORT=587

# Per-operation IMAP timeout in seconds (clamped to 1..=300)
# EMAIL_OPERATION_TIMEOUT=30
```

For Gmail/Workspace use an app password (or XOAUTH2). A `email.toml` file is
also supported — see `email.toml.example`. Run the built-in `email_doctor`
tool for a safe, machine-readable diagnostic of your configuration.

## Tool surface

| Area | Tools |
|---|---|
| **Read** | `list_emails`, `list_emails_with_headers`, `get_email`, `get_email_raw`, `search_emails`, `get_bodystructure`, `download_attachment` |
| **Folders** | `list_folders`, `create_folder`, `delete_folder`, `rename_folder`, `list_namespaces` |
| **Organize** | `move_email`, `move_thread`, `copy_email`, `delete_email`, `batch_delete`, `flag_email`, `mark_seen`, `batch_mark_seen` |
| **Drafts & send** | `create_draft`, `update_draft`, `list_drafts`, `send_email` |
| **Ops** | `get_quota`, `email_doctor`, `idle_wait` |

Read tools carry a `readOnlyHint`; mutations and `send_email` are intended to
pass through your client's approval gate.

## Security

- Credentials are taken from the environment or a local config file and are
  never persisted or logged by the server.
- `.env`, `.env.local`, `email.toml`, and `tokens/` are git-ignored — keep your
  real credentials out of version control.
- All IMAP/SMTP traffic uses TLS (rustls).

## Building and testing

```bash
cargo build --release
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## License

Apache-2.0. See [LICENSE](LICENSE).
