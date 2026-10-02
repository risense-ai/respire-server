const enc = (s) => new TextEncoder().encode(s);
const HEX = '0123456789abcdef';

export function toHex(b) {
  let s = '';
  for (const x of b) s += HEX[x >> 4] + HEX[x & 15];
  return s;
}

export function fromHex(h) {
  const a = new Uint8Array(h.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16);
  return a;
}

const hasSubtle = globalThis.crypto && crypto.subtle;

function sha256(bytes) {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const H0 = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const len = bytes.length;
  const bitLenHi = Math.floor(len / 0x20000000);
  const bitLenLo = (len << 3) >>> 0;
  const withPad = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  withPad.set(bytes);
  withPad[len] = 0x80;
  const dv = new DataView(withPad.buffer);
  dv.setUint32(withPad.length - 8, bitLenHi, false);
  dv.setUint32(withPad.length - 4, bitLenLo, false);
  const w = new Uint32Array(64);
  const h = new Uint32Array(H0);
  for (let off = 0; off < withPad.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0;
    h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0;
    h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0;
    h[7] = (h[7] + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, h[i], false);
  return out;
}

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

function hmacSha256(key, msg) {
  const block = 64;
  const k = key.length > block ? sha256(key) : key;
  const kp = new Uint8Array(block);
  kp.set(k);
  const ipad = new Uint8Array(block);
  const opad = new Uint8Array(block);
  for (let i = 0; i < block; i++) {
    ipad[i] = kp[i] ^ 0x36;
    opad[i] = kp[i] ^ 0x5c;
  }
  const inner = new Uint8Array(ipad.length + msg.length);
  inner.set(ipad);
  inner.set(msg, ipad.length);
  const outer = new Uint8Array(opad.length + 32);
  outer.set(opad);
  outer.set(sha256(inner), opad.length);
  return sha256(outer);
}

function pbkdf2Sha256(pass, salt, iter, dkLen) {
  const out = new Uint8Array(dkLen);
  const hLen = 32;
  let pos = 0;
  let block = 1;
  const saltWith = new Uint8Array(salt.length + 4);
  while (pos < dkLen) {
    saltWith.set(salt);
    saltWith[salt.length] = (block >>> 24) & 0xff;
    saltWith[salt.length + 1] = (block >>> 16) & 0xff;
    saltWith[salt.length + 2] = (block >>> 8) & 0xff;
    saltWith[salt.length + 3] = block & 0xff;
    let u = hmacSha256(pass, saltWith);
    const t = new Uint8Array(hLen);
    t.set(u);
    for (let i = 1; i < iter; i++) {
      u = hmacSha256(pass, u);
      for (let j = 0; j < hLen; j++) t[j] ^= u[j];
    }
    out.set(t.subarray(0, Math.min(hLen, dkLen - pos)), pos);
    pos += hLen;
    block++;
  }
  return out;
}

function hkdfSha256(ikm, salt, info, len) {
  const prk = hmacSha256(salt, ikm);
  const out = new Uint8Array(len);
  let t = new Uint8Array(0);
  let n = 0;
  let i = 1;
  const infoB = info || new Uint8Array(0);
  while (n < len) {
    const block = new Uint8Array(t.length + infoB.length + 1);
    block.set(t);
    block.set(infoB, t.length);
    block[t.length + infoB.length] = i;
    t = hmacSha256(prk, block);
    out.set(t.subarray(0, Math.min(32, len - n)), n);
    n += 32;
    i++;
  }
  return out;
}

export async function deriveSalt(user) {
  const ikm = enc(user.trim().toLowerCase());
  if (hasSubtle) {
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc('onememory:auth-salt:v1') },
      key,
      128,
    );
    return toHex(new Uint8Array(bits));
  }
  return toHex(hkdfSha256(ikm, new Uint8Array(32), enc('onememory:auth-salt:v1'), 16));
}

export async function deriveHash(pass, saltHex) {
  const salt = fromHex(saltHex);
  if (hasSubtle) {
    const key = await crypto.subtle.importKey('raw', enc(pass), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 },
      key,
      256,
    );
    return toHex(new Uint8Array(bits));
  }
  return toHex(pbkdf2Sha256(enc(pass), salt, 100000, 32));
}

export async function authPayload(user, password) {
  const salt = await deriveSalt(user);
  const pass_hash = await deriveHash(password, salt);
  return { user: user.trim(), pass_hash, salt };
}

const SUPER_ITERS = 210000;

function randomBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

export function generateSecretKey() {
  const raw = toHex(randomBytes(18));
  return `A3-${raw.slice(0, 6)}-${raw.slice(6, 12)}-${raw.slice(12, 18)}-${raw.slice(18, 24)}-${raw.slice(24, 30)}-${raw.slice(30, 36)}`;
}

async function deriveSuperKek(superPass, salt) {
  if (hasSubtle) {
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: SUPER_ITERS },
      await crypto.subtle.importKey('raw', enc(superPass), 'PBKDF2', false, ['deriveBits']),
      256,
    ));
  }
  return pbkdf2Sha256(enc(superPass), salt, SUPER_ITERS, 32);
}

async function deriveVaultKek(superPass, secretKey, salt) {
  const intermediate = await deriveSuperKek(superPass, salt);
  if (hasSubtle) {
    const key = await crypto.subtle.importKey('raw', intermediate, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc(secretKey), info: enc('onememory:kek:v1') },
      key,
      256,
    ));
  }
  return hkdfSha256(intermediate, enc(secretKey), enc('onememory:kek:v1'), 32);
}

// v4 single recovery-code factor; KEK = HKDF(entropy, salt=kdf_salt, info=kek:v4)

function superKeyBytes(superPass) {
  const body = superPass.trim().replace(/^A3-/, '');
  const raw = body.replace(/[^0-9a-fA-F]/g, '');
  if (raw.length !== 36) throw new Error('超级密码格式错误（应为 A3- 开头的 36 位恢复码）');
  return fromHex(raw);
}

async function deriveKekV4(superPass, saltHex) {
  const ikm = superKeyBytes(superPass);
  if (hasSubtle) {
    const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: fromHex(saltHex), info: enc('onememory:kek:v4') },
      key,
      256,
    ));
  }
  return hkdfSha256(ikm, fromHex(saltHex), enc('onememory:kek:v4'), 32);
}

export async function wrapVaultV4(superPass, urkBytes) {
  const kdfSalt = randomBytes(16);
  const kek = await deriveKekV4(superPass, toHex(kdfSalt));
  const nonce = randomBytes(12);
  const key = await crypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, urkBytes || randomBytes(32)));
  return { kdf_salt: toHex(kdfSalt), wrapped_urk: toHex(ct), urk_nonce: toHex(nonce), version: 4 };
}

async function unwrapVaultV4(superPass, vault) {
  const kek = await deriveKekV4(superPass, vault.kdf_salt);
  const key = await crypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromHex(vault.urk_nonce) },
    key,
    fromHex(vault.wrapped_urk),
  ));
}

export async function wrapVault(superPass, secretKey, urkBytes) {
  const salt = randomBytes(16);
  const kek = await deriveVaultKek(superPass, secretKey, salt);
  const urk = urkBytes || randomBytes(32);
  const nonce = randomBytes(12);
  const key = await crypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, urk));
  return { kdf_salt: toHex(salt), wrapped_urk: toHex(ct), urk_nonce: toHex(nonce), version: 3 };
}

export async function unwrapUrk(superPass, secretKey, vault) {
  const version = Number(vault.version);
  if (version >= 4) return unwrapVaultV4(secretKey || superPass, vault);
  const salt = fromHex(vault.kdf_salt);
  const kek = version === 3 ? await deriveVaultKek(superPass, secretKey, salt) : await deriveSuperKek(superPass, salt);
  const key = await crypto.subtle.importKey('raw', kek, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromHex(vault.urk_nonce) },
    key,
    fromHex(vault.wrapped_urk),
  ));
}

export async function deriveDataKey(urk) {
  if (hasSubtle) {
    const key = await crypto.subtle.importKey('raw', urk, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc('onememory:data:v1') },
      key,
      256,
    ));
  }
  return hkdfSha256(urk, new Uint8Array(32), enc('onememory:data:v1'), 32);
}

export async function decryptItem(dataKey, ciphertextHex, nonceHex) {
  const key = await crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, ['decrypt']);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromHex(nonceHex) },
    key,
    fromHex(ciphertextHex),
  );
  return new TextDecoder().decode(pt);
}

// Write encrypted entries using the same format as Rust crypto::encrypt_item.

/** Encrypt entry content with AES-256-GCM and a 12-byte nonce; return hex {nonce, ciphertext}. */
export async function encryptItem(dataKey, plaintext) {
  const key = await crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, ['encrypt']);
  const nonce = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    key,
    enc(plaintext),
  ));
  return { nonce: toHex(nonce), ciphertext: toHex(ct) };
}
