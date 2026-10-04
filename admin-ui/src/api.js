import { t } from './i18n.js';

export const USER_KEY = 'onememory.userToken';
export const ADMIN_KEY = 'onememory.adminToken';
export const SUPER_KEY = 'onememory.superPass';
export const SECRET_KEY = 'onememory.secretKey';
export const SUPER_AT_KEY = 'onememory.superPassAt';

// Locally saved recovery codes expire after three days; do not auto-unlock or prefill expired codes.
// Require manual entry after expiration and renew the timestamp on successful unlock.
export const SUPER_TTL_MS = 3 * 24 * 3600 * 1000;

let unauthorized = null;
export function onUnauthorized(handler) {
  unauthorized = handler;
}

export async function api(path, { method = 'GET', body, token } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  let payload;
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  }
  const response = await fetch(path, { method, headers, body: payload, cache: 'no-store' });
  const text = await response.text();
  let json = {};
  try {
    json = text ? JSON.parse(text) : {};
  } catch {
    json = { error: text };
  }
  if (response.status === 401 && unauthorized) unauthorized(path);
  if (
    response.status === 403
    && unauthorized
    && String(json.error || '').includes('admin token required')
  ) {
    unauthorized(path);
  }
  if (!response.ok) {
    const err = new Error(json.error || response.statusText || 'request failed');
    err.status = response.status;
    err.body = json;
    throw err;
  }
  return json;
}

export function readToken(key) {
  try {
    return localStorage.getItem(key) || '';
  } catch {
    return '';
  }
}

export function writeToken(key, value) {
  try {
    if (value) localStorage.setItem(key, value);
    else localStorage.removeItem(key);
  } catch {
    /* ignore quota */
  }
}

export function readSuper() {
  try {
    return localStorage.getItem(SUPER_KEY) || '';
  } catch {
    return '';
  }
}

export function writeSuper(value) {
  try {
    if (value) {
      localStorage.setItem(SUPER_KEY, value);
      localStorage.setItem(SUPER_AT_KEY, String(Date.now()));
    } else {
      localStorage.removeItem(SUPER_KEY);
      localStorage.removeItem(SUPER_AT_KEY);
    }
  } catch {
    /* ignore quota */
  }
}

export function readSecret() {
  try {
    return localStorage.getItem(SECRET_KEY) || '';
  } catch {
    return '';
  }
}

export function writeSecret(value) {
  try {
    if (value) localStorage.setItem(SECRET_KEY, value);
    else localStorage.removeItem(SECRET_KEY);
  } catch {
    /* ignore quota */
  }
}

// Check whether a locally stored recovery code is present and unexpired.
export function superFresh() {
  const saved = readSuper();
  if (!saved) return false;
  const at = Number(localStorage.getItem(SUPER_AT_KEY) || 0);
  if (!at) return false; // Treat older records without a timestamp as expired.
  return Date.now() - at < SUPER_TTL_MS;
}

// Expiration status text shared by the keys and locked pages.
export function superFreshText() {
  const saved = readSuper();
  if (!saved) return t('superNotSaved');
  const at = Number(localStorage.getItem(SUPER_AT_KEY) || 0);
  if (!at) return t('superExpiredNoTs');
  const remain = SUPER_TTL_MS - (Date.now() - at);
  if (remain <= 0) return t('superExpiredShort');
  const days = Math.floor(remain / (24 * 3600 * 1000));
  const hours = Math.floor((remain % (24 * 3600 * 1000)) / (3600 * 1000));
  return days > 0 ? t('superRemainDays', { days, hours }) : t('superRemainHours', { hours });
}
