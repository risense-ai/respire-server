import { useEffect, useMemo, useRef, useState } from 'react';
import {
  TreeStructure, Clock, MagnifyingGlass, CaretRight, LockKey, ShieldCheck,
  CloudCheck, Desktop, Terminal, Plus, Key, Copy, Check, Eye, EyeSlash, DownloadSimple,
  SignOut, ArrowClockwise, Article, ArrowLeft, X, WarningCircle, PencilSimple, Trash,
  ListBullets, CaretDown, BookOpen,
} from '@phosphor-icons/react';
import { Button, Badge, Heading, Empty, Note, SecretResult, copy, download, useI18n } from './ui.jsx';
import { decryptItem, deriveDataKey, encryptItem, generateSecretKey, unwrapUrk, wrapVaultV4 } from './crypto.js';
import { api, readSecret, readSuper, superFresh, superFreshText, writeSecret, writeSuper } from './api.js';
import { Security } from './Security.jsx';
import { buildIndex, childrenOf, subtreeCount, diaryDays, visibleRows, ROOT_ID, DIARY_ID } from './treeModel.js';
import { t, getLocale } from './i18n.js';

/** Normalize tags: CLI payloads may use CSV, while browser editing uses arrays. */
function toTagList(tags) {
  if (Array.isArray(tags)) return tags.filter(Boolean);
  if (typeof tags === 'string') return tags.split(',').map((t) => t.trim()).filter(Boolean);
  return [];
}
import DiaryCalendar from './DiaryCalendar.jsx';

function maskKey(s) {
  if (!s) return t('superNotSaved');
  if (s.length < 8) return '••••';
  return `${s.slice(0, 3)}-••••-••••-••••`;
}

const INSTALL_HINT = {
  zh: {
    title: '还没有记忆',
    body: '先从维护者取得经过验证的私有 Respire 构建，再运行 rsrs web 打开本地图形界面。',
    copy: '复制提示词',
    copied: '已复制',
    dismiss: '关闭',
    prompt: `帮我装好 Respire（唯一命令 rsrs，给我的 AI 用的跨设备记忆系统）。目前仓库和构建均私有，不假设公开 npm 包可用。全程自动执行，别中途停下问我：

1. 使用维护者提供且获准访问的私有构建安装 Respire，再跑 rsrs doctor 检查依赖。
2. 跑 rsrs inject，把记忆注入本机 AI 工具（必须在登录/注册之前完成）。
3. 问我要云同步还是离线：
   云同步 → 问我的用户名密码，执行 rsrs register --user <名> --pass <密码>，注册返回的【超级密码】必须展示给我、等我回复「已记好」才继续（丢了新设备解不开记忆），再跑 rsrs keys-export 提醒备份；
   离线 → 执行 rsrs keygen。
4. 跑一次 rsrs remember 和 rsrs recall 验收，最后告诉我可跑 rsrs web 开本地图形界面。`,
  },
  en: {
    title: 'No memories yet',
    body: 'Obtain a validated private Respire build from the maintainer, then run rsrs web to open the local GUI.',
    copy: 'Copy prompt',
    copied: 'Copied',
    dismiss: 'Dismiss',
    prompt: `Install Respire for me (sole command rsrs, a cross-device memory system for my AI). Repositories and builds are currently private; do not assume a public npm package is available. Do everything automatically; do not stop to ask me along the way:

1. Install an approved private build supplied by the maintainer, then run rsrs doctor to check dependencies.
2. Run rsrs inject to inject memory into local AI tools (must happen before login/register).
3. Ask whether I want cloud sync or offline:
   Cloud sync → ask for my username and password, run rsrs register --user <name> --pass <password>. You MUST show me the returned [super password] and wait until I reply "saved" before continuing (losing it means new devices cannot unlock memories), then run rsrs keys-export and remind me to back it up;
   Offline → run rsrs keygen.
4. Run rsrs remember and rsrs recall once to verify, then tell me I can run rsrs web to open the local GUI.`,
  },
};

function EmptyInstallHint({ notify }) {
  const { locale } = useI18n();
  const [lang, setLang] = useState(() => getLocale());
  useEffect(() => setLang(locale), [locale]);
  const [copied, setCopied] = useState(false);
  const [open, setOpen] = useState(() => {
    try { return sessionStorage.getItem('respire-empty-hint') !== 'dismissed'; } catch { return true; }
  });
  const copyTimer = useRef(null);
  useEffect(() => () => clearTimeout(copyTimer.current), []);
  if (!open) return null;
  const hint = INSTALL_HINT[lang] || INSTALL_HINT.en;
  const copyPrompt = async () => {
    try {
      await navigator.clipboard.writeText(hint.prompt);
      setCopied(true);
      notify(t('hintCopied'));
      clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2500);
    } catch {
      notify(t('hintCopyBlocked'));
    }
  };
  const dismiss = () => {
    try { sessionStorage.setItem('respire-empty-hint', 'dismissed'); } catch { /* private mode */ }
    setOpen(false);
  };
  return (
    <aside className="install-hint" role="status">
      <div className="install-hint-langs">
        <button type="button" aria-pressed={lang === 'zh'} onClick={() => setLang('zh')}>中文</button>
        <button type="button" aria-pressed={lang === 'en'} onClick={() => setLang('en')}>English</button>
      </div>
      <button type="button" className="icon-button install-hint-close" aria-label={hint.dismiss} onClick={dismiss}><X size={16} /></button>
      <h3>{hint.title}</h3>
      <p>{hint.body}</p>
      <pre>{hint.prompt}</pre>
      <div className="install-hint-actions">
        <Button primary icon={copied ? Check : Copy} onClick={copyPrompt}>{copied ? hint.copied : hint.copy}</Button>
      </div>
    </aside>
  );
}

export function DashboardPages({
  page, memoryId, token, me, sessions, keys, notify, open, go, onReload, onToken, onLogout,
}) {
  useI18n();
  const [query, setQuery] = useState('');
  const [items, setItems] = useState(null);
  const openMemory = (id) => go(id ? `memories/${encodeURIComponent(id)}` : 'memories');
  const [locked, setLocked] = useState(true);
  const [revealed, setRevealed] = useState(false);
  const [tick, setTick] = useState(0);
  const [vaultInfo, setVaultInfo] = useState(undefined);
  const [viewMode, setViewMode] = useState('tree');
  const [expanded, setExpanded] = useState(() => new Set([ROOT_ID, DIARY_ID]));
  // Memoize indexes and search results because TreeBranch depends on index identity.
  // Rebuilding them on every render would reset expanded child rows.
  const treeSource = useMemo(() => {
    const all = items || [];
    if (!query) return all;
    const q = query.toLowerCase();
    const hit = new Set();
    all.forEach((m) => {
      const hay = [m.title, m.content, m.kind, m.project, toTagList(m.tags).join(' ')].filter(Boolean).join(' ').toLowerCase();
      if (hay.includes(q)) hit.add(m.id);
    });
    const byId = new Map(all.map((m) => [m.id, m]));
    const keep = new Set(hit);
    hit.forEach((id) => {
      let cur = byId.get(id);
      let guard = 0;
      while (cur && cur.parent_id && guard++ < 64) {
        keep.add(cur.parent_id);
        cur = byId.get(cur.parent_id);
      }
    });
    return all.filter((m) => keep.has(m.id));
  }, [items, query]);
  // Keep text matches and their ancestors visible during search.
  const forceIds = useMemo(() => {
    if (!query) return null;
    const all = items || [];
    const q = query.toLowerCase();
    const keep = new Set();
    all.forEach((m) => {
      const hay = [m.title, m.content, m.kind, m.project, toTagList(m.tags).join(' ')].filter(Boolean).join(' ').toLowerCase();
      if (!hay.includes(q)) return;
      keep.add(m.id);
      let cur = m;
      let guard = 0;
      const byId = new Map(all.map((x) => [x.id, x]));
      while (cur && cur.parent_id && guard++ < 64) {
        keep.add(cur.parent_id);
        cur = byId.get(cur.parent_id);
      }
    });
    return keep;
  }, [items, query]);
  const treeIndex = useMemo(() => {
    const idx = buildIndex(treeSource);
    if (forceIds) idx.forceIds = forceIds;
    return idx;
  }, [treeSource, forceIds]);
  // Compute visible rows once, descending only into expanded levels.
  const treeRows = useMemo(() => visibleRows(treeIndex, expanded), [treeIndex, expanded]);
  const dataKeyRef = useRef(null);
  // Keep the incremental /pull cursor and active content key in refs.
  const cursorRef = useRef(null);
  const syncingRef = useRef(false);
  const trailingRef = useRef(false);
  const [syncing, setSyncing] = useState(false);
  const [lastSync, setLastSync] = useState(null);
  const saveMemory = async (payload, existingId) => {
    const dataKey = dataKeyRef.current;
    if (!dataKey) throw new Error(t('pleaseUnlock'));
    const now = new Date().toISOString();
    const id = existingId || crypto.randomUUID();
    const pt = JSON.stringify(payload);
    const { nonce, ciphertext } = await encryptItem(dataKey, pt);
    // The browser leaves embedding_enc empty; the CLI/Core builds the retrieval index after sync.
    // api() returns JSON and throws for non-2xx responses.
    await api('/push', { method: 'POST', body: { id, ciphertext, nonce, embedding_enc: '', updated_at: now, deleted: false }, token });
    // Newly pushed revisions exceed the cursor; merge incrementally rather than unlock everything again.
    await syncIncremental();
    return id;
  };
  const deleteMemory = async (id) => {
    await api('/forget', { method: 'POST', body: { id }, token });
    // forget writes a tombstone and advances the revision for incremental deletion.
    await syncIncremental();
  };
  const superPass = readSuper();
  const secretKey = readSecret();
  const keyStored = !!(superPass || secretKey);
  const hasVault = !!(vaultInfo && vaultInfo.wrapped_urk);

  useEffect(() => {
    if (page !== 'keys') return;
    api('/api/self/vault', { token })
      .then(setVaultInfo)
      .catch((e) => {
        if (e.status === 404) setVaultInfo(null);
        else notify(e.message);
      });
  }, [page, token, tick]);

  const unlockMemories = async (pass, secret) => {
    const vault = await api('/api/self/vault', { token });
    const v = Number(vault.version) || 0;
    if (v >= 4 && !pass) throw new Error(t('needSuper'));
    if (v === 3 && !pass) throw new Error(t('needSuperV3'));
    if (v === 3 && !secret) throw new Error(t('needSecretV3'));
    const urk = await unwrapUrk(pass, secret, vault);
    writeSuper(pass);
    if (v === 3 && secret) writeSecret(secret);
    const pull = await api('/pull', { token });
    const dataKey = await deriveDataKey(urk);
    dataKeyRef.current = dataKey;
    // The response cursor is captured before rows; later revisions remain available in subsequent pulls.
    cursorRef.current = pull.cursor;
    const out = [];
    let failed = 0;
    for (const blob of pull.blobs || []) {
      if (blob.deleted) continue;
      try {
        const payload = JSON.parse(await decryptItem(dataKey, blob.ciphertext, blob.nonce));
        out.push({ id: blob.id, ...payload });
      } catch { failed++; }
    }
    setItems(out);
    setLocked(false);
    setLastSync(Date.now());
    setExpanded((prev) => {
      const next = new Set(prev);
      next.add(ROOT_ID);
      next.add(DIARY_ID);
      return next;
    });
    if (failed > 0) {
      notify(t('unlockedPartial', { ok: out.length, fail: failed }));
    }
  };

  // Incremental sync pulls changed blobs and tombstones after the cursor and merges locally decrypted content.
  // Keep the previous local version when a new ciphertext cannot be decrypted.
  const syncIncremental = async () => {
    if (syncingRef.current) { trailingRef.current = true; return; }
    const dataKey = dataKeyRef.current;
    if (!dataKey) return;
    syncingRef.current = true;
    setSyncing(true);
    try {
      const since = cursorRef.current;
      const pull = await api(since == null ? '/pull' : `/pull?since=${encodeURIComponent(since)}`, { token });
      // Locking or unlocking during await can clear or replace the dataKeyRef object.
      // Check object identity before merging plaintext into the active session.
      if (dataKeyRef.current !== dataKey) return;
      cursorRef.current = pull.cursor;
      const changed = pull.blobs || [];
      if (changed.length) {
        const ups = new Map();
        let failed = 0;
        for (const blob of changed) {
          if (blob.deleted) { ups.set(blob.id, null); continue; }
          try {
            const payload = JSON.parse(await decryptItem(dataKey, blob.ciphertext, blob.nonce));
            ups.set(blob.id, { id: blob.id, ...payload });
          } catch { failed++; }
        }
        // Recheck session identity after decrypting entries and before merging.
        if (dataKeyRef.current !== dataKey) return;
        setItems((prev) => {
          const next = new Map((prev || []).map((m) => [m.id, m]));
          for (const [id, mem] of ups.entries()) {
            if (mem === null) next.delete(id);
            else next.set(id, mem);
          }
          return [...next.values()];
        });
        if (failed > 0) notify(t('newCipherFail', { n: failed }));
      }
      setLastSync(Date.now());
    } finally {
      syncingRef.current = false;
      setSyncing(false);
      const runTrailing = trailingRef.current;
      trailingRef.current = false;
      if (runTrailing && dataKeyRef.current) {
        syncIncremental().catch(() => { /* Retry on the next poll */ });
      }
    }
  };

  // Locking clears key material and invalidates in-flight sync by dataKeyRef identity.
  // Never render returned plaintext after the user locks the view.
  const lockMemories = () => {
    dataKeyRef.current = null;
    setLocked(true);
    setItems(null);
  };

  // Poll every four seconds while unlocked; pause when hidden and sync on becoming visible.
  // Skip polling while locked.
  const unlocked = !locked && items !== null;
  useEffect(() => {
    if (!unlocked) return;
    let stopped = false;
    let timer = 0;
    const tick = async () => {
      if (stopped) return;
      if (document.visibilityState === 'visible') {
        try { await syncIncremental(); } catch { /* Global handling reports network/auth errors; retry on the next poll */ }
      }
      if (!stopped) timer = window.setTimeout(tick, 4000);
    };
    timer = window.setTimeout(tick, 4000);
    const onVisible = () => {
      if (document.visibilityState === 'visible') {
        // syncIncremental propagates rejections; attach .catch for asynchronous calls.
        syncIncremental().catch(() => { /* Retry transient network errors on the next poll */ });
      }
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      stopped = true;
      window.clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [unlocked, token]);

  useEffect(() => {
    if (page !== 'memories') return;
    if (items !== null) return;
    const saved = readSuper();
    if (!saved) return;
    // Saved recovery codes expire after three days; request manual entry instead of auto-unlocking.
    if (!superFresh()) { setLocked(true); return; }
    unlockMemories(saved, readSecret()).catch((e) => {
      setLocked(true);
      const why = String(e.message || e);
      const hint = e.status === 404
        ? t('noVault')
        : why.includes('Secret Key')
          ? t('missingSecret')
          : t('unlockFail', { why });
      notify(hint);
    });
  }, [page, token]);

  const openNewMemory = () => open({
    title: t('saveOne'),
    icon: Plus,
    description: t('saveOneDesc'),
    fields: [
      { name: 'title', label: t('fieldTitle'), required: true, placeholder: t('titlePh') },
      { name: 'content', label: t('fieldContent'), type: 'textarea', rows: 8, required: true, placeholder: t('contentPh') },
      { name: 'kind', label: t('fieldKind'), options: [
        { value: 'context', label: t('kindContext') },
        { value: 'decision', label: t('kindDecision') },
        { value: 'task', label: t('kindTask') },
        { value: 'preference', label: t('kindPreference') },
        { value: 'skill', label: t('kindSkill') },
        { value: 'emotion', label: t('kindEmotion') },
        { value: 'time', label: t('kindTime') },
      ] },
      { name: 'importance', label: t('fieldImportance'), options: [['important', 'important'], ['trivial', 'trivial']] },
      { name: 'project', label: t('fieldProject'), required: false },
      { name: 'tags', label: t('fieldTags'), required: false },
    ],
    onSubmit: async (v) => {
      await saveMemory({
        kind: v.kind, title: v.title, content: v.content, importance: v.importance,
        tags: v.tags, project: v.project, parent_id: '',
        user: me?.user || '', computer: 'dashboard', device: 'dashboard', modified_by: 'dashboard',
        emotion: -1, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      });
      notify(t('uploaded'));
    },
    submit: t('encryptUpload'),
  });
  const openEditMemory = (m) => open({
    title: t('editMemory'),
    icon: PencilSimple,
    fields: [
      { name: 'title', label: t('fieldTitle'), required: true, value: m.title || '' },
      { name: 'content', label: t('fieldContent'), type: 'textarea', rows: 8, required: true, value: m.content || '' },
      { name: 'kind', label: t('fieldKind'), options: [
        { value: 'context', label: t('kindContext') },
        { value: 'decision', label: t('kindDecision') },
        { value: 'task', label: t('kindTask') },
        { value: 'preference', label: t('kindPreference') },
        { value: 'skill', label: t('kindSkill') },
        { value: 'emotion', label: t('kindEmotion') },
        { value: 'time', label: t('kindTime') },
      ], value: m.kind || 'context' },
      { name: 'importance', label: t('fieldImportance'), options: [['important', 'important'], ['trivial', 'trivial']], value: m.importance === 'trivial' ? 'trivial' : 'important' },
      { name: 'project', label: t('fieldProject'), required: false, value: m.project || '' },
      { name: 'tags', label: t('fieldTags'), required: false, value: toTagList(m.tags).join(',') },
    ],
    onSubmit: async (v) => {
      await saveMemory({
        ...m,
        kind: v.kind, title: v.title, content: v.content, importance: v.importance,
        tags: v.tags ? v.tags.split(',').map((t) => t.trim()).filter(Boolean) : [],
        project: v.project,
        updated_at: new Date().toISOString(), modified_by: 'dashboard',
      }, m.id);
      openMemory(null);
      notify(t('savedEdit'));
    },
    submit: t('saveEdit'),
  });
  const openUnlock = async () => {
    let vault = {};
    try { vault = await api('/api/self/vault', { token }); } catch { /* Report a missing vault on submission */ }
    const v = Number(vault.version) || 0;
    const fresh = superFresh();
    const saved = readSuper();
    // Do not prefill an expired saved recovery code.
    const prefill = fresh ? saved : '';
    const fields = v >= 4
      ? [{ name: 'pass', label: t('labelSuperA3'), type: 'password', value: prefill }]
      : [
          { name: 'pass', label: t('labelSuperPass'), type: 'password', value: prefill },
          { name: 'secret', label: 'Secret Key', value: fresh ? readSecret() : '', required: false },
        ];
    open({
      title: t('unlockTitle'),
      icon: LockKey,
      description: (
        (v >= 4
          ? (fresh ? t('unlockV4Fresh') : t('unlockV4'))
          : (fresh ? t('unlockV3Fresh') : t('unlockV3')))
        + t('unlockTail')
      ),
      fields,
      onSubmit: async (vals) => {
        await unlockMemories(vals.pass, vals.secret);
        notify(t('unlockedHere'));
      },
      submit: t('unlockView'),
    });
  };

  if (page === 'diary') {
    const all = items || [];
    const trivials = all.filter((m) => m.importance === 'trivial');
    const dayMap = new Map();
    trivials.forEach((m) => {
      const trail = (m.title || '').match(/^活动轨迹 (\d{4}-\d{2}-\d{2})$/);
      const iso = m.created_at || m.updated_at || '';
      const d = new Date(iso);
      const localDay = Number.isNaN(d.getTime())
        ? String(iso).slice(0, 10)
        : `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
      const day = (trail && trail[1]) || localDay || 'unknown-date';
      if (!dayMap.has(day)) dayMap.set(day, []);
      dayMap.get(day).push({ id: m.id, title: m.title || t('untitled') });
    });
    const days = [...dayMap.keys()].sort().reverse().map((day) => ({ day, items: dayMap.get(day) }));
    if (locked && items === null) {
      return (
        <>
          <Heading eyebrow="YOUR DIARY / ACTIVITY" title={t('diaryTitle')} description={t('diaryDesc')} />
          <section className="locked-state panel">
            <div className="large-mark"><BookOpen size={40} /></div>
            <Badge tone="purple">{t('e2e')}</Badge>
            <h2>{t('diaryLockedH2')}</h2>
            <p>{t('diaryLockedP')}</p>
            <Button primary icon={Key} onClick={openUnlock}>{t('unlockMemory')}</Button>
          </section>
        </>
      );
    }
    return (
      <>
        <Heading eyebrow="YOUR DIARY / ACTIVITY" title={t('diaryTitle')} description={t('diaryCount', { n: trivials.length, d: days.length })}>
          <Button icon={ArrowLeft} onClick={() => go('memories')}>{t('backToTree')}</Button>
        </Heading>
        <section className="panel" style={{ padding: 22 }}>
          <DiaryCalendar days={days} onOpenMemory={(id) => openMemory(id)} />
        </section>
      </>
    );
  }

  if (page === 'memories') {
    const list = (items || []).filter((m) => [m.title, m.content, m.kind, m.project].filter(Boolean).join(' ').toLowerCase().includes(query.toLowerCase()));
    const mem = (items || []).find((m) => m.id === memoryId);
    if (locked && items === null) {
      return (
        <>
          <Heading eyebrow="YOUR MEMORY / YOUR CONTEXT" title={t('myMemory')} description={t('myMemoryDesc')} />
          <section className="locked-state panel">
            <div className="large-mark"><LockKey size={40} /></div>
            <Badge tone="purple">{t('e2e')}</Badge>
            <h2>{t('lockedH2')}</h2>
            <p>
              {readSuper() && !superFresh()
                ? <>{t('superExpired')}<br /></>
                : null}
              {t('lockedP')}
            </p>
            <Button primary icon={Key} onClick={openUnlock}>{t('unlockMemory')}</Button>
            <span>{readSuper() ? t('localKeyStatus', { status: superFreshText() }) : t('cipherLocal')}</span>
          </section>
        </>
      );
    }
    const emptyVault = Array.isArray(items) && items.length === 0;
    return (
      <>
        <Heading eyebrow="YOUR MEMORY / YOUR CONTEXT" title={mem ? (mem.title || t('untitled')) : t('myMemory')} description={mem ? t('alongMemory') : t('myMemoryDesc')}>
          {mem ? <Button icon={ArrowLeft} onClick={() => openMemory(null)}>{t('backMemory')}</Button> : (
            <>
              <Button primary icon={Plus} onClick={openNewMemory}>{t('saveMemory')}</Button>
              <Button icon={viewMode === 'tree' ? ListBullets : TreeStructure} onClick={() => setViewMode(viewMode === 'tree' ? 'list' : 'tree')}>{viewMode === 'tree' ? t('listView') : t('treeView')}</Button>
              <Button icon={ArrowClockwise} onClick={() => unlockMemories(readSuper(), readSecret()).then(() => notify(t('pulled'))).catch((e) => notify(e.message))}>{t('pullLatest')}</Button>
              <Button icon={LockKey} onClick={() => { lockMemories(); openMemory(null); notify(t('locked')); }}>{t('lock')}</Button>
            </>
          )}
        </Heading>
        {mem ? (
          <div className="memory-reading">
            <article className="reading-main">
              <div className="reading-meta"><Badge tone="purple">{mem.kind || t('memoryKind')}</Badge><span>{mem.project || '—'} · {mem.updated_at || mem.created_at}</span></div>
              <h2>{t('memoryBody')}</h2>
              {renderContent(mem.content)}
              <div className="reading-footer"><LockKey size={17} />{t('onlyHere')}</div>
            </article>
            <aside className="inspector panel">
              <div className="section-top"><h2>{t('memoryInfo')}</h2></div>
              <dl className="details">
                <div><dt>{t('memoryType')}</dt><dd>{mem.kind || '—'}</dd></div>
                <div><dt>{t('project')}</dt><dd>{mem.project || '—'}</dd></div>
                <div><dt>{t('updatedAt')}</dt><dd>{mem.updated_at || mem.created_at || '—'}</dd></div>
                <div><dt>{t('memoryId')}</dt><dd><button className="copy-id" onClick={() => copy(mem.id, notify)}>{mem.id}<Copy size={15} /></button></dd></div>
              </dl>
              <Note>{t('inspectNote')}</Note>
              <div className="key-actions">
                <Button icon={PencilSimple} onClick={() => openEditMemory(mem)}>{t('edit')}</Button>
              </div>
              <Button danger icon={Trash} onClick={() => open({
                title: t('deleteMemoryQ'),
                description: t('deleteMemoryDesc', { title: mem.title || t('untitled') }),
                danger: true,
                fields: [{ name: 'confirm', label: t('typeDelete') }],
                validate: (v) => (v.confirm !== t('deleteWord') ? t('pleaseTypeDelete') : null),
                onSubmit: async () => { await deleteMemory(mem.id); openMemory(null); notify(t('deleted')); },
                submit: t('deleteWord'),
              })}>{t('deleteMemory')}</Button>
            </aside>
          </div>
        ) : (
          <>
            {emptyVault && <EmptyInstallHint notify={notify} />}
            <div className="memory-status">
              <span><CloudCheck size={22} />{t('cloudReady')}</span>
              <span>{t('nMemories', { n: (items || []).length })}</span>
              <span className="green-text"><ShieldCheck size={18} />{t('browserUnlocked')}</span>
              <span className={`sync-indicator${syncing ? ' is-syncing' : ''}`}>
                <span className="sync-dot" aria-hidden="true" />
                {syncing ? t('syncing') : lastSync ? t('autoSynced', { time: new Date(lastSync).toLocaleTimeString(getLocale() === 'zh' ? 'zh-CN' : 'en-US', { hour12: false }) }) : t('autoSyncOn')}
              </span>
            </div>
            <section className="memory-collection panel" style={{ padding: 20 }}>
              <label className="search-box memory-search">
                <MagnifyingGlass size={21} />
                <input aria-label={t('searchMemory')} placeholder={t('searchPh')} value={query} onChange={(e) => setQuery(e.target.value)} />
                {query && <button className="icon-button" aria-label={t('clear')} onClick={() => setQuery('')}><X size={17} /></button>}
              </label>
              <div className="collection-title"><h2>{query ? t('searchResults') : (viewMode === 'tree' ? t('memoryTree') : t('allMemories'))}</h2><span>{t('nItems', { n: viewMode === 'tree' ? treeSource.length : list.length })}</span></div>
              {query && list.length ? (
                <div className="search-results">
                  {list.slice(0, 200).map((m) => {
                    const path = [];
                    let cur = m;
                    let guard = 0;
                    const byId = new Map((items || []).map((x) => [x.id, x]));
                    while (cur && cur.parent_id && guard++ < 32) {
                      const par = byId.get(cur.parent_id);
                      if (!par) break;
                      path.unshift(par.title || t('untitled'));
                      cur = par;
                    }
                    return (
                      <button key={m.id} className="search-hit" onClick={() => openMemory(m.id)}>
                        <Article size={16} />
                        <span className="hit-main">
                          <strong>{m.title || t('untitled')}</strong>
                          <small>{(m.content || '').replace(/\s+/g, ' ').slice(0, 90)}</small>
                          {path.length ? <em>{path.join(' › ')}</em> : null}
                        </span>
                      </button>
                    );
                  })}
                  {list.length > 200 ? <p className="hit-more">{t('hitMore', { n: list.length })}</p> : null}
                </div>
              ) : viewMode === 'tree' && treeSource.length ? (
                <div className="tree-view">
                  {treeRows.map(({ row, depth, open, hasKids }) => (
                    <div key={row.id} className={`tree-row${memoryId === row.memoryId ? ' active' : ''}`} style={{ paddingLeft: 8 + depth * 18 }}>
                      {hasKids ? (
                        <button className="tree-toggle" aria-label={t('expandFold')} onClick={() => setExpanded((prev) => {
                          const next = new Set(prev);
                          if (next.has(row.id)) next.delete(row.id); else next.add(row.id);
                          return next;
                        })}>
                          <CaretDown size={14} style={{ transform: open ? 'none' : 'rotate(-90deg)', transition: 'transform .15s' }} />
                        </button>
                      ) : <span className="tree-toggle-placeholder" />}
                      {row.kind === 'memory' && !hasKids ? (
                        <button className="tree-leaf" onClick={() => openMemory(row.memoryId)}>
                          <Article size={15} />
                          <span>{row.title}</span>
                        </button>
                      ) : (
                        <span className="tree-folder" onClick={() => setExpanded((prev) => {
                          const next = new Set(prev);
                          if (next.has(row.id)) next.delete(row.id); else next.add(row.id);
                          return next;
                        })}>
                          <strong>{row.title}</strong>
                          {open ? <small>{t('nItems', { n: row.kids || 0 })}</small> : null}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
              <div className="memory-list">
                {list.map((m) => (
                  <div className="memory-row" key={m.id}>
                    <button className="memory-item" onClick={() => openMemory(m.id)}>
                      <span className="memory-icon purple"><Article size={23} /></span>
                      <span>
                        <strong>{m.title || t('untitled')}</strong>
                        <p>{(m.content || '').slice(0, 80)}</p>
                        <small>{m.kind || t('memoryKind')} · {m.project || '—'}</small>
                      </span>
                      <CaretRight size={20} />
                    </button>
                  </div>
                ))}
                {!list.length && !emptyVault && <Empty title={t('noMemoryFound')} text={t('noMemoryHint')} />}
              </div>
              )}
            </section>
          </>
        )}
      </>
    );
  }

  if (page === 'sessions') {
    return (
      <>
        <Heading eyebrow="YOUR ACCOUNT / SESSIONS" title={t('sessionsTitle')} description={t('sessionsDesc')}>
          <Button primary icon={Plus} onClick={() => open({
            title: t('createNewSession'),
            icon: Desktop,
            fields: [{ name: 'name', label: t('deviceName'), placeholder: t('devicePh'), value: 'dashboard' }],
            onSubmit: async (v) => {
              const reply = await api('/api/self/sessions', { method: 'POST', token, body: { device_name: v.name || 'web' } });
              notify(t('sessionCreated'));
              onReload();
              open({
                title: t('saveSessionToken'),
                body: <SecretResult value={reply.token} notify={notify} description={t('tokenOnce')} />,
                submit: t('iSaved'),
              });
            },
            submit: t('mintToken'),
          })}>{t('createSession')}</Button>
        </Heading>
        <div className="session-summary">
          <div className="large-mark"><Desktop size={31} /></div>
          <div><h2>{t('nSessions', { n: sessions.length })}</h2><p>{t('sessionsLead')}</p></div>
          <Badge tone="green"><ShieldCheck size={16} />{t('connectionProtected')}</Badge>
        </div>
        <section className="panel">
          <div className="section-top"><h2>{t('connectedDevices')}</h2></div>
          {sessions.map((s) => {
            const I = /cli|terminal/i.test(s.device_name || '') ? Terminal : Desktop;
            return (
              <div className="session-row" key={s.id}>
                <span className="device-mark"><I size={28} /></span>
                <div><h3>{s.device_name}{s.current ? <Badge tone="purple">{t('currentSession')}</Badge> : null}</h3><p>{s.created_at}</p></div>
                <Button danger onClick={async () => {
                  await api(`/api/self/sessions/${s.id}/revoke`, { method: 'POST', token });
                  notify(t('sessionRevoked'));
                  if (s.current) onLogout();
                  else onReload();
                }}>{t('revoke')}</Button>
              </div>
            );
          })}
          {!sessions.length && <Empty title={t('noSessions')} text={t('noSessionsHint')} />}
        </section>
        <div className="setting-row plain">
          <div><h3>{t('rotateMain')}</h3><p>{t('rotateMainP')}</p></div>
          <Button icon={ArrowClockwise} onClick={async () => {
            const reply = await api('/api/self/rotate', { method: 'POST', token });
            onToken(reply.token);
            notify(t('rotated'));
            open({
              title: t('newMainToken'),
              body: <SecretResult value={reply.token} notify={notify} description={t('updateDevices')} />,
              submit: t('saved'),
            });
          }}>{t('rotateToken')}</Button>
        </div>
      </>
    );
  }

  const issueVault = async ({ reset }) => {
    // v4 recovery codes are generated rather than chosen by the user.
    const newSuper = generateSecretKey();
    const wrapped = await wrapVaultV4(newSuper);
    await api('/api/self/vault', { method: 'POST', token, body: wrapped });
    writeSuper(newSuper);
    writeSecret('');
    setTick((n) => n + 1);
    lockMemories();
    notify(reset ? t('keysResetLost') : t('superGenerated'));
    window.setTimeout(() => open({
      title: t('copySuperNowTitle'),
      body: <SecretResult value={newSuper} notify={notify} description={t('copySuperNowBody', { reset: reset ? t('copySuperNowReset') : '' })} />,
      submit: t('iCopied'),
    }), 0);
  };

  if (page === 'keys') {
    return (
      <>
        <Heading eyebrow="YOUR ACCOUNT / ENCRYPTION" title={t('keysTitle')} description={t('keysDesc')} />
        <div className="key-hero">
          <div className="large-mark"><Key size={35} /></div>
          <div>
            <h2>{t('keysHeroH2')}</h2>
            <p style={{ whiteSpace: 'pre-line' }}>{t('keysHeroP')}</p>
          </div>
          <Badge tone={hasVault ? 'green' : 'amber'}>{hasVault ? `Vault v${vaultInfo.version || 4}` : t('vaultNotSet')}</Badge>
        </div>
        {!hasVault && vaultInfo !== undefined ? (
          <Note icon={WarningCircle} tone="amber">{t('noWrap')}</Note>
        ) : null}
        <section className="panel key-panel">
          <div className="section-top"><h2>{t('keysInBrowser')}</h2><Badge tone={keyStored ? (superFresh() ? 'green' : 'amber') : 'amber'}>{keyStored ? (superFresh() ? t('savedInTtl') : t('expired')) : t('notSaved')}</Badge></div>
          <div className="key-row"><div><label>{t('superPassword')}</label><p>{t('superExplain', { status: superPass ? t('currentStatus', { status: superFreshText() }) : '' })}</p></div><code>{superPass ? (revealed ? superPass : '••••••••••••••••') : t('superNotSaved')}</code></div>
          <div className="key-row">
            <div><label>{t('superPassword')}</label><p>{t('superSame')}</p></div>
            <code>{revealed && secretKey ? secretKey : maskKey(secretKey)}</code>
            <button aria-label={t('showHide')} className="icon-button" disabled={!keyStored} onClick={() => setRevealed(!revealed)}>{revealed ? <EyeSlash size={22} /> : <Eye size={22} />}</button>
          </div>
          <div className="key-actions">
            <Button icon={DownloadSimple} disabled={!keyStored} onClick={() => {
              download('respire-recovery.txt', t('recoveryFile', { pass: superPass || secretKey }));
              notify(t('recoveryDownloaded'));
            }}>{t('downloadRecovery')}</Button>
            <Button icon={Copy} disabled={!keyStored} onClick={() => copy(superPass || secretKey, notify)}>{t('copySuper')}</Button>
          </div>
        </section>
        <div className="settings-stack">
          {!hasVault ? (
            <div className="setting-row">
              <div><h3>{t('genSuperH3')}</h3><p>{t('genSuperP')}</p></div>
              <Button primary onClick={async () => {
                try {
                  const pull = await api('/pull', { token });
                  if ((pull.total || 0) > 0) {
                    notify(t('cloudHasNoWrap', { n: pull.total }));
                    return;
                  }
                  await issueVault({ reset: false });
                } catch (e) { notify(e.message); }
              }}>{t('generateSuper')}</Button>
            </div>
          ) : (
            <div className="setting-row">
              <div><h3>{t('resetSuperH3')}</h3><p>{t('resetSuperP')}</p></div>
              <Button onClick={() => open({
                title: t('resetSuperTitle'),
                description: t('resetSuperDesc'),
                fields: [
                  { name: 'old', label: t('currentSuper'), type: 'password', value: readSuper() },
                ],
                onSubmit: async (v) => {
                  const vault = await api('/api/self/vault', { token });
                  const urk = await unwrapUrk(v.old, readSecret(), vault);
                  const newSuper = generateSecretKey();
                  const wrapped = await wrapVaultV4(newSuper, urk);
                  await api('/api/self/vault', { method: 'POST', token, body: wrapped });
                  writeSuper(newSuper);
                  writeSecret('');
                  setTick((n) => n + 1);
                  lockMemories();
                  window.setTimeout(() => open({
                    title: t('copyNewSuper'),
                    body: <SecretResult value={newSuper} notify={notify} description={t('oldSuperVoid')} />,
                    submit: t('iCopied'),
                  }), 0);
                  notify(t('superResetOk'));
                },
                submit: t('resetGen'),
              })}>{t('reset')}</Button>
            </div>
          )}
          {hasVault && Number(vaultInfo?.version) <= 3 ? (
            <div className="setting-row">
              <div><h3>{t('upgradeV4')}</h3><p>{t('upgradeV4P')}</p></div>
              <Badge tone="amber">v{vaultInfo?.version || 3}</Badge>
            </div>
          ) : null}
          {hasVault ? (
            <div className="setting-row">
              <div><h3>{t('resetKeysH3')}</h3><p>{t('resetKeysP')}</p></div>
              <Button danger onClick={() => open({
                title: t('resetKeysTitle'),
                description: t('resetKeysDesc'),
                danger: true,
                fields: [
                  { name: 'confirm', label: t('typeConfirmReset') },
                ],
                validate: (v) => (v.confirm !== t('confirmResetWord') ? t('pleaseTypeConfirmReset') : null),
                onSubmit: async (v) => { await issueVault({ reset: true }); },
                submit: t('confirmResetAbandon'),
              })}>{t('reset')}</Button>
            </div>
          ) : null}
          <div className="setting-row">
            <div><h3>{keyStored ? t('removeLocalKeys') : t('saveLocalKeys')}</h3><p>{keyStored ? t('removeLocalP') : t('saveLocalP')}</p></div>
            <Button danger={keyStored} onClick={() => {
              if (keyStored) {
                writeSuper(''); writeSecret('');
                lockMemories(); setRevealed(false); setTick((n) => n + 1);
                notify(t('removedLocal'));
              } else {
                openUnlock();
              }
            }}>{keyStored ? t('remove') : t('saveKeys')}</Button>
          </div>
        </div>
        <Note icon={WarningCircle} tone="amber">{t('keepSuperSafe')}</Note>
      </>
    );
  }

  return <Security admin={false} token={token} me={me} notify={notify} onReload={onReload} open={open} onLogout={onLogout} />;
}

/**
 * Render both single line breaks and blank-line paragraph separators in CLI content.
 * Preserve original line breaks and indentation within each paragraph.
 * Render bracketed section markers in separate blocks with a left border.
 */
function renderContent(content) {
  const raw = String(content || '').replace(/\r\n/g, '\n').trim();
  if (!raw) return <p className="reading-empty">{t('emptyBody')}</p>;
  // CLI content may join bracketed section markers without line breaks.
  // Insert line breaks before section markers while preserving adjacent context.
  const text = raw.replace(/(?<![\n])(【[^】]{1,12}】)/g, '\n$1').trim();
  const blocks = text.split(/\n\s*\n/).filter((b) => b.trim());
  return blocks.map((block, bi) => {
    const lines = block.split('\n').filter((l) => l.trim());
    const isMarked = lines.length > 1 && lines.some((l) => /^【.+?】/.test(l.trim()));
    if (isMarked) {
      return (
        <div className="reading-block is-marked" key={bi}>
          {lines.map((line, li) => {
            const m = line.trim().match(/^【(.+?)】\s*(.*)$/);
            if (m) return <p className="marked-line" key={li}><span className="marked-tag">{m[1]}</span><span>{m[2]}</span></p>;
            return <p className="plain-line" key={li}>{line}</p>;
          })}
        </div>
      );
    }
    if (lines.length === 1) return <p key={bi}>{lines[0]}</p>;
    return (
      <div className="reading-block" key={bi}>
        {lines.map((line, li) => <p className="plain-line" key={li}>{line}</p>)}
      </div>
    );
  });
}

/** Render tree branches on demand by loading children only for expanded nodes. */
function TreeRows({ index, parentId, depth, expanded, onToggle, onSelect, selected, onCount }) {
  // Compute child rows synchronously with useMemo when index or parentId changes.
  const rows = useMemo(() => childrenOf(index, parentId), [index, parentId]);
  return (rows || []).map((row) => {
    const isFolder = row.kind === 'folder' || row.kids > 0;
    const open = expanded.has(row.id);
    return (
      <div key={row.id}>
        <div className={`tree-row${selected === row.memoryId ? ' active' : ''}`} style={{ paddingLeft: 8 + depth * 18 }}>
          {isFolder ? (
            <button className="tree-toggle" aria-label={t('expandFold')} onClick={() => onToggle(row.id)}>
              <CaretDown size={14} style={{ transform: open ? 'none' : 'rotate(-90deg)', transition: 'transform .15s' }} />
            </button>
          ) : <span className="tree-toggle-placeholder" />}
          {row.kind === 'memory' && !isFolder ? (
            <button className="tree-leaf" onClick={() => onSelect(row.memoryId)}>
              <Article size={15} />
              <span>{row.title}</span>
            </button>
          ) : (
            <span className="tree-folder" onClick={() => onToggle(row.id)}>
              <strong>{row.title}</strong>
              {open ? <small>{row.id === DIARY_ID ? t('nDays', { n: row.kids }) : t('nItems', { n: (onCount ? onCount(row.id) : row.kids) || 0 })}</small> : null}
            </span>
          )}
        </div>
        {open ? (
          <TreeRows
            index={index}
            parentId={row.id}
            depth={depth + 1}
            expanded={expanded}
            onToggle={onToggle}
            onSelect={onSelect}
            selected={selected}
            onCount={onCount}
          />
        ) : null}
      </div>
    );
  });
}
