// Memory tree model: index the data once and load visible children on demand.
//
// buildIndex constructs the parent-to-child index in O(n), without building a complete node tree.
// childrenOf(index, id) loads only the direct children when a node is expanded.
// This avoids reconstructing the entire tree for each row.
//
// Hierarchy: root, top-level memories and diary, dates, then trivial entries.

export const ROOT_ID = 'tree-root';
export const DIARY_ID = 'diary-book';
const DAY_PREFIX = 'diary-day-';

// Use local dates; slicing UTC created_at would assign early morning entries to the previous day.
function localDayOf(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso).slice(0, 10);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

// Diary titles contain the authoritative local date assigned by the CLI.
function activityDayOf(title) {
  return /^活动轨迹 (\d{4}-\d{2}-\d{2})$/.exec(title || '')?.[1] || '';
}

/** Build parent-to-child and diary-date-to-entry indexes in O(n). */
export function buildIndex(memories = []) {
  const ids = new Set(memories.map((m) => m.id));
  const byParent = new Map(); // parentId (root is '') to memory rows
  const diaryByDay = new Map(); // 'YYYY-MM-DD' to trivial entries
  const contentless = new Set(); // IDs of entries without a title or body
  const categoryRoot = new Set(); // Category roots whose content contains a short category description
  memories.forEach((m) => {
    const row = {
      id: m.id,
      memoryId: m.id,
      title: m.title || String(m.id || '').slice(0, 8),
    };
    const hasBody = Boolean((m.title || '').trim() || (m.content || '').trim());
    if (!hasBody) contentless.add(m.id);
    // Recognize category roots by a title-prefixed, single-paragraph description.
    const t = (m.title || '').trim();
    const c = (m.content || '').trim();
    if (t && c.startsWith(t + '：') && c.split('\n\n').length <= 2 && c.length < 260) {
      categoryRoot.add(m.id);
    }
    if (m.importance === 'trivial') {
      const day = activityDayOf(m.title) || localDayOf(m.created_at || m.updated_at) || 'unknown-date';
      if (!diaryByDay.has(day)) diaryByDay.set(day, []);
      diaryByDay.get(day).push(row);
      return;
    }
    const pid = m.parent_id && ids.has(m.parent_id) ? m.parent_id : '';
    if (!byParent.has(pid)) byParent.set(pid, []);
    byParent.get(pid).push(row);
  });
  return { byParent, diaryByDay, ids, contentless, categoryRoot, days: [...diaryByDay.keys()].sort().reverse() };
}

/** Load direct children on demand, without descendants; kids is the direct child count. */
export function childrenOf(index, nodeId) {
  const { byParent, diaryByDay, days, contentless, categoryRoot } = index;
  // Hide empty leaf entries and category roots that contain only a description.
  // Keep every node that has children.
  // forceIds keeps search matches and their ancestors visible despite empty-node filtering.
  const forceIds = index.forceIds || new Set();
  const visible = (r) => {
    if (forceIds.has(r.id)) return true;
    const kids = (byParent.get(r.id) || []).length;
    if (kids > 0) return true;
    if (contentless.has(r.id)) return false;
    if (categoryRoot.has(r.id)) return false;
    return true;
  };
  if (!nodeId || nodeId === ROOT_ID) {
    const rows = (byParent.get('') || [])
      .filter(visible)
      .map((r) => ({ ...r, kind: 'memory', kids: (byParent.get(r.id) || []).length }));
    // The diary uses its own #/diary page rather than a tree placeholder.
    return rows;
  }
  if (nodeId === DIARY_ID) {
    return days.map((d) => ({
      id: DAY_PREFIX + d,
      kind: 'folder',
      title: d,
      kids: (diaryByDay.get(d) || []).length,
    }));
  }
  if (nodeId.startsWith(DAY_PREFIX)) {
    const day = nodeId.slice(DAY_PREFIX.length);
    return (diaryByDay.get(day) || []).map((r) => ({ ...r, kind: 'memory', kids: 0 }));
  }
  return (byParent.get(nodeId) || [])
    .filter(visible)
    .map((r) => ({ ...r, kind: 'memory', kids: (byParent.get(r.id) || []).length }));
}

/**
 * Flatten visible rows from the root, descending only into expanded nodes.
 * Each visible level costs O(children); return [{row, depth}] for list rendering.
 * Compute once without child component effect ordering.
 */
export function visibleRows(index, expanded) {
  const out = [];
  const walk = (parentId, depth) => {
    if (depth > 24) return; // Bound pathological tree depth
    childrenOf(index, parentId).forEach((row) => {
      const hasKids = row.kind === 'folder' || row.kids > 0;
      out.push({ row, depth, open: expanded.has(row.id), hasKids });
      if (hasKids && expanded.has(row.id)) walk(row.id, depth + 1);
    });
  };
  walk(ROOT_ID, 0);
  return out;
}

/** Group diary entries by date in descending order for DiaryCalendar. */
export function diaryDays(index) {
  const { diaryByDay, days } = index;
  return days.map((day) => ({
    day,
    items: (diaryByDay.get(day) || []).map((r) => ({ id: r.id, title: r.title })),
  }));
}

/** Count descendants only when a node is expanded, avoiding full recursion for every row. */
export function subtreeCount(index, nodeId) {
  let total = 0;
  const stack = [nodeId];
  const seen = new Set();
  while (stack.length) {
    const cur = stack.pop();
    if (seen.has(cur)) continue;
    seen.add(cur);
    childrenOf(index, cur).forEach((row) => {
      total += 1;
      stack.push(row.id);
    });
  }
  return total;
}
