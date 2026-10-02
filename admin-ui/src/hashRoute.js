/** Dashboard and Admin hash routes; #/memories/<id> supports browser back navigation. */

export function parseRoute(hash, { admin, fallback, pageIds }) {
  const parts = String(hash || '').replace(/^#\/?/, '').split('/').filter(Boolean);
  const off = (parts[0] === 'admin' || parts[0] === 'dashboard') ? 1 : 0;
  const pageSeg = parts[off];
  const page = pageIds.includes(pageSeg) ? pageSeg : fallback;
  let memoryId = null;
  if (!admin && pageSeg === 'memories' && parts[off + 1]) {
    try {
      memoryId = decodeURIComponent(parts[off + 1]);
    } catch {
      memoryId = parts[off + 1];
    }
  }
  return { page, memoryId };
}

/** Convert dashboard memory pathnames to hash routes while preserving the subpath. */
export function pathRestToHash(rest) {
  const cleaned = String(rest || '').replace(/^\/+|\/+$/g, '').split(/[?#]/)[0];
  return cleaned ? `#/${cleaned}` : '#/';
}

export function routeHash(page, memoryId) {
  if (!page) return '#/';
  if (page === 'memories' && memoryId) return `#/memories/${encodeURIComponent(memoryId)}`;
  return `#/${page}`;
}
