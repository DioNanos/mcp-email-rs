#!/usr/bin/env bash
# install.sh — download and install a prebuilt mcp-email-rs binary from the
# GitHub releases of DioNanos/mcp-email-rs.
#
# What it does:
#   1. resolves the release (latest, or pinned with --version), detects OS and
#      architecture and picks the matching release asset (Linux x86_64/aarch64,
#      glibc or musl, and Termux/Android);
#   2. downloads the archive plus its .sha256 checksum and verifies it
#      (mismatch = hard failure, never install on a bad checksum);
#   3. stages the new binary next to the destination, verifies that it runs and
#      that its reported version matches the requested release, backs up the
#      current binary (timestamped .bak), and only then swaps it in with an
#      atomic same-directory rename. Any failure before or after the swap
#      restores the previous binary and leaves no temporary files behind;
#   4. runs a final `--version` smoke test on the installed binary.
#
# On macOS there is no prebuilt binary: the script prints the equivalent
# `cargo install --git --locked --tag <release>` command (the release is
# resolved even there, so "latest" really means the latest release) and exits.
#
# Usage:
#   ./install.sh [--version vX.Y.Z] [--prefix DIR] [--bin-name NAME] [--target TRIPLE]
#
#   --version vX.Y.Z   install a specific release (default: latest release).
#                      The installed binary's --version output must match, or
#                      the install is rolled back.
#   --prefix DIR       install root (default: $HOME/.local); binary goes to $prefix/bin
#   --bin-name NAME    name of the installed binary (default: mcp-email-rs).
#                      Only the installed name changes: the archive member is
#                      always the upstream `mcp-email-rs` binary.
#   --target TRIPLE    force a target triple instead of auto-detecting
#
# Dependencies: curl or wget, tar, sha256sum (or shasum -a 256), uname.
# Never touches credentials, never uses sudo, only writes under --prefix.
# MCP_EMAIL_RS_RELEASE_BASE overrides the download base URL (mirrors/tests).

set -euo pipefail

REPO="DioNanos/mcp-email-rs"
SOURCE_MEMBER="mcp-email-rs"          # the binary name inside the archives
BIN_NAME="mcp-email-rs"               # the installed name at the destination
PREFIX="${HOME}/.local"
VERSION=""
FORCE_TARGET=""
BASE_URL="${MCP_EMAIL_RS_RELEASE_BASE:-}"

log()  { printf '%s\n' "[install] $*"; }
die()  { printf '%s\n' "[install] ERROR: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version)  VERSION="${2:?missing value}"; shift 2 ;;
        --prefix)   PREFIX="${2:?missing value}"; shift 2 ;;
        --bin-name) BIN_NAME="${2:?missing value}"; shift 2 ;;
        --target)   FORCE_TARGET="${2:?missing value}"; shift 2 ;;
        *) die "unknown option: $1 (see header for usage)" ;;
    esac
done

# --- minimal HTTP fetch: curl first, wget as fallback ----------------------
fetch() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" -o "$2"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$2" "$1"
    else
        die "need curl or wget to download from GitHub releases"
    fi
}

# --- checksum tool: sha256sum first, shasum -a 256 as fallback -------------
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d' ' -f1
    else
        die "need sha256sum or shasum to verify the downloaded archive"
    fi
}

# --- resolve the release first: every branch below pins to it ---------------
if [ -z "$VERSION" ]; then
    log "looking up the latest release..."
    if command -v curl >/dev/null 2>&1; then
        VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    else
        VERSION="$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    fi
    [ -n "$VERSION" ] || die "could not determine the latest release from GitHub API"
fi
if [ -z "$BASE_URL" ]; then
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
fi

# --- OS gate ----------------------------------------------------------------
OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
    log "no prebuilt binary for this OS ($OS)."
    if [ "$OS" = "Darwin" ]; then
        log "install from source instead (Rust toolchain required):"
        printf '  cargo install --git https://github.com/%s --tag %s --locked\n' "$REPO" "$VERSION"
        exit 0
    fi
    die "unsupported OS: $OS"
fi

# --- architecture / target triple ------------------------------------------
ARCH="$(uname -m)"
LIBC="gnu"
# musl detection: Alpine (ldd is BusyBox) or an explicit musl in ldd output.
if command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    LIBC="musl"
fi
case "$ARCH:$LIBC" in
    x86_64:gnu)  TARGET="x86_64-unknown-linux-gnu" ;;
    x86_64:musl) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64:gnu) TARGET="aarch64-unknown-linux-gnu" ;;
    aarch64:musl) TARGET="aarch64-unknown-linux-musl" ;;
    *) die "unsupported architecture: $ARCH (libc: $LIBC)" ;;
esac
# Termux/Android: the Android prebuilt is built for Termux (linker64, NDK).
case "${PREFIX}" in /data/data/com.termux*) IN_TERMUX_PREFIX=true ;; *) IN_TERMUX_PREFIX=false ;; esac
if [ "$ARCH" = "aarch64" ] && { [ -n "${TERMUX_VERSION:-}" ] || [ -n "${TERMUX_MAIN_PACKAGE_FORMAT:-}" ] || $IN_TERMUX_PREFIX; }; then
    TARGET="aarch64-linux-android"
fi
if [ -n "$FORCE_TARGET" ]; then TARGET="$FORCE_TARGET"; fi
log "release: $VERSION · target: $TARGET"

ARCHIVE="mcp-email-rs-${TARGET}.tar.gz"
WORKDIR="$(mktemp -d)"

# --- transaction state -------------------------------------------------------
# The live binary is never removed: the new one is staged, verified and made
# executable first; the old binary is backed up by COPY (not moved away); the
# only mutation is one atomic rename. Anything failing before that rename
# leaves the live binary untouched (the redundant .bak copy is removed again);
# anything failing after the rename restores the previous binary when one
# exists, or removes the broken candidate on a first install. STAGED is always
# cleaned up, and a bin/ directory created by this run is removed again if it
# ends up empty. The final state must match what the messages say.
BACKUP=""
STAGED=""
COMMITTED=0
# Every directory of the chain that does not exist yet is recorded BEFORE any
# mkdir -p runs (deepest first), so the rollback can take the whole created
# chain back and the final filesystem matches the initial one. The walk stops
# at $HOME and at /: nothing above $HOME is ever created or removed.
# The list is a bash ARRAY: paths can contain spaces and glob characters, and
# a space-joined string would word-split and pathname-expand (a literal
# `victim*` prefix could otherwise retract a sibling `victimSAFE/`).
CREATED_DIRS=()
record_created_chain() {
    local dir="$1"
    while [ ! -d "$dir" ]; do
        CREATED_DIRS+=("$dir")
        if [ "$dir" = "$HOME" ]; then break; fi
        dir="$(dirname "$dir")"
        if [ "$dir" = "/" ]; then break; fi
    done
}

cleanup() {
    if [ -n "$STAGED" ]; then rm -f "$STAGED"; fi
    if [ "$COMMITTED" -eq 0 ]; then
        # Nothing was swapped in: the redundant backup copy of an untouched
        # live binary is removed again, so "destination untouched" stays true.
        if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
            rm -f "$BACKUP"
        fi
        # Retract the directories this run created, deepest first, each one
        # only if it is still empty.
        for d in ${CREATED_DIRS[@]+"${CREATED_DIRS[@]}"}; do
            if [ -d "$d" ] && [ -z "$(ls -A "$d")" ]; then rmdir "$d" 2>/dev/null || true; fi
        done
    fi
    rm -rf "$WORKDIR"
}
trap cleanup EXIT

# --- download ----------------------------------------------------------------
log "downloading ${ARCHIVE}..."
fetch "${BASE_URL}/${ARCHIVE}" "${WORKDIR}/${ARCHIVE}"
fetch "${BASE_URL}/${ARCHIVE}.sha256" "${WORKDIR}/${ARCHIVE}.sha256"

# --- verify checksum (fail-closed) --------------------------------------------
EXPECTED="$(cut -d' ' -f1 "${WORKDIR}/${ARCHIVE}.sha256" | tr '[:upper:]' '[:lower:]')"
[ -n "$EXPECTED" ] || die "empty checksum file"
ACTUAL="$(sha256_of "${WORKDIR}/${ARCHIVE}")"
if [ "$ACTUAL" != "$EXPECTED" ]; then
    # Some releases checksum the binary inside the archive instead of the
    # archive itself: extract first, then compare the binary's checksum.
    tar -xzf "${WORKDIR}/${ARCHIVE}" -C "$WORKDIR"
    SOURCE_BIN="$(find "$WORKDIR" -type f -name "${SOURCE_MEMBER}" | head -1)"
    [ -n "$SOURCE_BIN" ] || die "checksum mismatch and no ${SOURCE_MEMBER} binary found in the archive"
    ACTUAL="$(sha256_of "$SOURCE_BIN")"
    [ "$ACTUAL" = "$EXPECTED" ] || die "checksum MISMATCH: expected ${EXPECTED}, got ${ACTUAL} — refusing to install"
fi
log "checksum verified (${EXPECTED:0:12}...)"

# --- extract -------------------------------------------------------------------
if [ ! -f "${SOURCE_BIN:-}" ]; then
    tar -xzf "${WORKDIR}/${ARCHIVE}" -C "$WORKDIR"
fi
SOURCE_BIN="$(find "$WORKDIR" -type f -name "${SOURCE_MEMBER}" | head -1)"
[ -n "$SOURCE_BIN" ] || die "no ${SOURCE_MEMBER} binary found inside the archive"

# --- version pin on the STAGED binary, before touching the destination --------
BIN_DIR="${PREFIX}/bin"
BIN_PATH="${BIN_DIR}/${BIN_NAME}"
STAGED="${BIN_DIR}/.${BIN_NAME}.staged.$$"
record_created_chain "$BIN_DIR"
mkdir -p "$BIN_DIR"
cp "$SOURCE_BIN" "$STAGED"
chmod 0755 "$STAGED"
if ! STAGED_OUT="$("$STAGED" --version 2>&1)"; then
    die "smoke test on the staged binary failed; destination untouched"
fi
if [ -n "$VERSION" ]; then
    REQUESTED="${VERSION#v}"
    REQUESTED_RE="${REQUESTED//./\\.}"
    if ! printf '%s\n' "$STAGED_OUT" | grep -Eq "(^|[[:space:]])${REQUESTED_RE}\$"; then
        die "version pin mismatch: requested ${VERSION}, staged binary reports '${STAGED_OUT}' — destination untouched"
    fi
fi

# --- backup (by copy: the live binary stays in place) --------------------------
if [ -f "$BIN_PATH" ]; then
    BACKUP="${BIN_PATH}.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$BIN_PATH" "$BACKUP"
    log "existing binary backed up to ${BACKUP}"
fi

# --- atomic swap ----------------------------------------------------------------
mv -f "$STAGED" "$BIN_PATH"
COMMITTED=1

# --- smoke + version pin on the INSTALLED binary --------------------------------
if ! LIVE_OUT="$("$BIN_PATH" --version 2>&1)"; then
    if [ -n "$BACKUP" ]; then
        cp -p "$BACKUP" "$BIN_PATH"
        log "smoke test on the installed binary failed (${LIVE_OUT})"
        log "rolled back to the previous binary (backup kept at ${BACKUP})"
        die "install rolled back to the previous binary"
    else
        rm -f "$BIN_PATH"
        COMMITTED=0
        # First install: the EXIT cleanup takes back every directory this run
        # created, so the filesystem returns to its initial state.
        log "smoke test on the installed binary failed (${LIVE_OUT})"
        die "first install rolled back: the broken candidate was removed, no binary is installed"
    fi
fi
if [ -n "$VERSION" ]; then
    if ! printf '%s\n' "$LIVE_OUT" | grep -Eq "(^|[[:space:]])${REQUESTED_RE}\$"; then
        if [ -n "$BACKUP" ]; then
            cp -p "$BACKUP" "$BIN_PATH"
            die "version pin mismatch after install: requested ${VERSION}, installed binary reports '${LIVE_OUT}' — rolled back to the previous binary (kept at ${BACKUP})"
        else
            rm -f "$BIN_PATH"
            COMMITTED=0
            die "version pin mismatch after install: requested ${VERSION}, installed binary reports '${LIVE_OUT}' — first install rolled back, no binary is installed"
        fi
    fi
fi
log "installed ${BIN_PATH}"
log "note: live MCP sessions keep the OLD binary until the session is restarted."
log "done."
