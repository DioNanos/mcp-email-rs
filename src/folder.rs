/// Common folder name detection across providers
use std::borrow::Cow;

pub fn find_drafts_folder(folders: &[FolderInfo]) -> Option<String> {
    let drafts_names = [
        "Drafts",
        "[Gmail]/Drafts",
        "INBOX.Drafts",
        "Draft",
        "Bozze",
        "[Gmail]/Bozze",
        "Bozza",
        "Brouillons",
        "[Gmail]/Brouillons",
        "Entw&APw-rfe",
    ];

    for name in &drafts_names {
        if let Some(f) = folders.iter().find(|f| f.name == *name) {
            return Some(f.name.clone());
        }
    }
    None
}

pub fn find_sent_folder(folders: &[FolderInfo]) -> Option<String> {
    let sent_names = [
        "Sent",
        "[Gmail]/Sent Mail",
        "INBOX.Sent",
        "Sent Items",
        "Sent Messages",
        "Posta inviata",
        "[Gmail]/Posta inviata",
        "Messages envoy&AOk-s",
        "[Gmail]/Messages envoy&AOk-s",
        "Gesendet",
        "[Gmail]/Gesendet",
    ];

    for name in &sent_names {
        if let Some(f) = folders.iter().find(|f| f.name == *name) {
            return Some(f.name.clone());
        }
    }
    None
}

pub fn find_trash_folder(folders: &[FolderInfo]) -> Option<String> {
    let trash_names = [
        "Trash",
        "[Gmail]/Trash",
        "INBOX.Trash",
        "Deleted Items",
        "Deleted Messages",
        "Cestino",
        "[Gmail]/Cestino",
        "Corbeille",
        "[Gmail]/Corbeille",
        "Papierkorb",
        "[Gmail]/Papierkorb",
    ];

    for name in &trash_names {
        if let Some(f) = folders.iter().find(|f| f.name == *name) {
            return Some(f.name.clone());
        }
    }
    None
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FolderInfo {
    pub name: String,
    pub delimiter: String,
    pub flags: Vec<String>,
}

impl FolderInfo {
    pub fn from_imap_name(name: async_imap::types::Name) -> Self {
        Self {
            name: name.name().to_string(),
            delimiter: name.delimiter().map(|d| d.to_string()).unwrap_or_default(),
            flags: name.attributes().iter().map(|f| format!("{f:?}")).collect(),
        }
    }

    pub fn is_selectable(&self) -> bool {
        !self.flags.iter().any(|f| f.contains("NoSelect"))
    }
}

/// Normalize thread subject by stripping Re:/Fwd:/Fw: prefixes
pub fn normalize_thread_subject(subject: &str) -> String {
    let s = subject.trim();
    let prefixes = ["Re: ", "RE: ", "Fwd: ", "FWD: ", "Fw: ", "FW: "];

    let mut result = s.to_string();
    loop {
        let mut stripped = false;
        for prefix in &prefixes {
            if result.starts_with(prefix) {
                result = result[prefix.len()..].to_string();
                stripped = true;
                break;
            }
        }
        if !stripped {
            break;
        }
    }
    result.trim().to_string()
}

/// Encode a folder name to IMAP modified UTF-7.
/// Normalizes delimiter to IMAP format and encodes non-ASCII chars.
/// Handles: `Doc.Contabilità.VIVIenergia` → `Doc/Contabilit&AOA-/VIVIenergia`
pub fn encode_folder_for_imap(folder: &str, imap_delimiter: char) -> Cow<'_, str> {
    // First normalize delimiter: if user sent `.` but IMAP uses `/`
    let normalized: Cow<'_, str> =
        if imap_delimiter != '.' && folder.contains('.') && !folder.contains(imap_delimiter) {
            Cow::Owned(folder.replace('.', &imap_delimiter.to_string()))
        } else {
            Cow::Borrowed(folder)
        };

    // Check if UTF-7 encoding is needed (any char > 0x7F or `&` which needs escaping)
    let needs_utf7 = normalized.chars().any(|c| c as u32 > 0x7F || c == '&');
    if !needs_utf7 {
        return normalized;
    }

    // Encode each path segment separately
    let segments: Vec<&str> = normalized.split(imap_delimiter).collect();
    let mut encoded_parts = Vec::with_capacity(segments.len());

    for segment in segments {
        encoded_parts.push(encode_utf7_modified(segment));
    }

    Cow::Owned(encoded_parts.join(&imap_delimiter.to_string()))
}

/// Encode a single folder name segment to modified UTF-7
fn encode_utf7_modified(input: &str) -> String {
    // Check if encoding is needed
    let all_ascii_no_amp = input.chars().all(|c| c.is_ascii() && c != '&');
    if all_ascii_no_amp {
        return input.to_string();
    }

    // Modified UTF-7: encode non-ASCII chars using base64 (without padding, no + prefix)
    // All printable ASCII chars pass through, & becomes &-
    // Non-ASCII chars are encoded as &base64-
    let mut output = String::new();
    let mut pending_utf16 = Vec::new();

    for ch in input.chars() {
        if ch == '&' {
            // Flush pending
            if !pending_utf16.is_empty() {
                output.push('&');
                output.push_str(&encode_base64_mod(&pending_utf16));
                output.push('-');
                pending_utf16.clear();
            }
            output.push_str("&-"); // Escaped &
        } else if ch.is_ascii() && ch != '\0' {
            // Flush pending before ASCII
            if !pending_utf16.is_empty() {
                output.push('&');
                output.push_str(&encode_base64_mod(&pending_utf16));
                output.push('-');
                pending_utf16.clear();
            }
            output.push(ch);
        } else {
            // Non-ASCII char: accumulate UTF-16BE
            pending_utf16.push(ch);
        }
    }

    // Flush remaining
    if !pending_utf16.is_empty() {
        output.push('&');
        output.push_str(&encode_base64_mod(&pending_utf16));
        output.push('-');
    }

    output
}

/// Base64 encode for modified UTF-7 (no padding, RFC 3501 base64 alphabet)
fn encode_base64_mod(chars: &[char]) -> String {
    // Convert chars to UTF-16BE bytes
    let mut bytes = Vec::new();
    for ch in chars {
        let code = *ch as u32;
        bytes.push((code >> 8) as u8);
        bytes.push(code as u8);
    }

    // Modified base64: use IMAP alphabet (+/ → +,) and no padding
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

    let mut result = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i] as u32;
        let b1 = if i + 1 < bytes.len() {
            bytes[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < bytes.len() {
            bytes[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(BASE64_CHARS[(triple >> 18) as usize] as char);
        result.push(BASE64_CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < bytes.len() {
            result.push(BASE64_CHARS[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < bytes.len() {
            result.push(BASE64_CHARS[(triple & 0x3F) as usize] as char);
        }

        i += 3;
    }

    result
}

/// Decode a folder name from IMAP modified UTF-7 to display form
pub fn decode_folder_from_imap(imap_name: &str, imap_delimiter: char) -> String {
    let segments: Vec<&str> = imap_name.split(imap_delimiter).collect();
    let mut decoded_parts = Vec::with_capacity(segments.len());

    for segment in segments {
        decoded_parts.push(decode_utf7_modified(segment));
    }

    // Always return with `.` as delimiter for display
    decoded_parts.join(".")
}

/// Decode a single segment from modified UTF-7
fn decode_utf7_modified(input: &str) -> String {
    if !input.contains('&') {
        return input.to_string();
    }

    let mut output = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '&' {
            match chars.peek() {
                Some(&'-') => {
                    // Escaped &
                    chars.next();
                    output.push('&');
                }
                Some(_) => {
                    // Start of base64 encoded sequence
                    let mut b64 = String::new();
                    while let Some(&next) = chars.peek() {
                        if next == '-' {
                            chars.next();
                            break;
                        }
                        // Convert IMAP modified base64 (, → /)
                        let c = if next == ',' { '/' } else { next };
                        b64.push(c);
                        chars.next();
                    }
                    // Decode base64 to UTF-16BE
                    let bytes = decode_base64_mod(&b64);
                    let mut i = 0;
                    while i + 1 < bytes.len() {
                        let code = ((bytes[i] as u16) << 8) | (bytes[i + 1] as u16);
                        if let Some(ch) = char::from_u32(code as u32) {
                            output.push(ch);
                        }
                        i += 2;
                    }
                }
                None => {
                    // Trailing &
                    output.push('&');
                }
            }
        } else {
            output.push(ch);
        }
    }

    output
}

/// Decode base64 string (standard alphabet)
fn decode_base64_mod(input: &str) -> Vec<u8> {
    // Simple base64 decode
    const BASE64_INDEX: [u8; 256] = {
        let mut table = [255u8; 256];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < chars.len() {
            table[chars[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    let mut result = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i + 3 < bytes.len() {
        let b0 = BASE64_INDEX[bytes[i] as usize] as u32;
        let b1 = BASE64_INDEX[bytes[i + 1] as usize] as u32;
        let b2 = BASE64_INDEX[bytes[i + 2] as usize] as u32;
        let b3 = BASE64_INDEX[bytes[i + 3] as usize] as u32;

        if b0 == 255 || b1 == 255 || b2 == 255 || b3 == 255 {
            i += 4;
            continue;
        }

        let triple = (b0 << 18) | (b1 << 12) | (b2 << 6) | b3;
        result.push(((triple >> 16) & 0xFF) as u8);
        result.push(((triple >> 8) & 0xFF) as u8);
        result.push((triple & 0xFF) as u8);
        i += 4;
    }

    // Handle remaining bytes
    let remaining = bytes.len() - i;
    if remaining >= 2 {
        let b0 = BASE64_INDEX[bytes[i] as usize] as u32;
        let b1 = BASE64_INDEX[bytes[i + 1] as usize] as u32;
        let triple = (b0 << 18) | (b1 << 12);
        result.push(((triple >> 16) & 0xFF) as u8);
        if remaining >= 3 {
            let b2 = BASE64_INDEX[bytes[i + 2] as usize] as u32;
            let triple = (b0 << 18) | (b1 << 12) | (b2 << 6);
            result.push(((triple >> 8) & 0xFF) as u8);
        }
    }

    result
}
