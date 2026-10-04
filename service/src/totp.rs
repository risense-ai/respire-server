//! TOTP (RFC 6238, SHA-1, 6 digits, 30s). Secret is unpadded RFC 4648 Base32.

use hmac::{Hmac, Mac};
use respire::memory::crypto::random_bytes;
use sha1::Sha1;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn new_secret() -> String {
    encode(&random_bytes(20))
}

pub fn otpauth(account: &str, secret: &str) -> String {
    format!("otpauth://totp/respire:{account}?secret={secret}&issuer=respire&period=30&digits=6")
}

pub fn generate(secret: &str, unix: i64) -> Option<String> {
    let key = decode(secret)?;
    let counter = (unix / 30) as u64;
    let hmac = hmac_sha1(&key, counter).ok()?;
    Some(digits(&hmac))
}

pub fn verify(secret: &str, code: &str, unix: i64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    for skew in [-1, 0, 1] {
        if let Some(expect) = generate(secret, unix + skew * 30) {
            if expect == code {
                return true;
            }
        }
    }
    false
}

fn hmac_sha1(key: &[u8], counter: u64) -> Result<[u8; 20], anyhow::Error> {
    let mut mac = Hmac::<Sha1>::new_from_slice(key)
        .map_err(|e| anyhow::anyhow!("HMAC-SHA1 init failed: {e}"))?;
    mac.update(&counter.to_be_bytes());
    let out = mac.finalize().into_bytes();
    let mut raw = [0u8; 20];
    raw.copy_from_slice(&out);
    Ok(raw)
}

fn digits(hmac: &[u8; 20]) -> String {
    let offset = (hmac[19] & 0x0f) as usize;
    let bin = ((u32::from(hmac[offset]) & 0x7f) << 24)
        | (u32::from(hmac[offset + 1]) << 16)
        | (u32::from(hmac[offset + 2]) << 8)
        | u32::from(hmac[offset + 3]);
    format!("{:06}", bin % 1_000_000)
}

fn encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut buf = 0u32;
    let mut n = 0;
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(ALPHABET[((buf >> n) & 31) as usize] as char);
        }
    }
    if n > 0 {
        out.push(ALPHABET[((buf << (5 - n)) & 31) as usize] as char);
    }
    out
}

fn decode(s: &str) -> Option<Vec<u8>> {
    let mut buf = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        let u = c.to_ascii_uppercase() as u8;
        let v = ALPHABET.iter().position(|&a| a == u)? as u32;
        buf = (buf << 5) | v;
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((buf >> n) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_window() -> anyhow::Result<()> {
        let secret = new_secret();
        let now = 1_700_000_000;
        let code = generate(&secret, now).ok_or_else(|| anyhow::anyhow!("totp generate"))?;
        assert!(verify(&secret, &code, now));
        assert!(verify(&secret, &code, now + 20));
        assert!(!verify(&secret, "000000", now));
        assert_eq!(
            decode(&secret).ok_or_else(|| anyhow::anyhow!("totp decode"))?.len(),
            20
        );
        Ok(())
    }
}
