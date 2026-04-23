//! Fixed-capacity text matching helpers shared across correlation internals.

pub(crate) fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let haystack_bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.len() > haystack_bytes.len() {
        return false;
    }

    for start in 0..=(haystack_bytes.len() - needle_bytes.len()) {
        let mut matched = true;
        for offset in 0..needle_bytes.len() {
            if !haystack_bytes[start + offset].eq_ignore_ascii_case(&needle_bytes[offset]) {
                matched = false;
                break;
            }
        }

        if matched {
            return true;
        }
    }

    false
}

pub(crate) fn hash_ascii_case_insensitive(text: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in text.as_bytes() {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    hash
}

pub(crate) fn copy_str_to_buffer(source: &str, out: &mut [u8]) -> usize {
    let bytes = source.as_bytes();
    let copy_len = bytes.len().min(out.len());
    out[..copy_len].copy_from_slice(&bytes[..copy_len]);
    copy_len
}
