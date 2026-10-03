import { useEffect, useRef, useState } from 'react';
import {
  Users, ShieldCheck, Clock, Envelope, LockKey, TreeStructure, Desktop, Key,
  MagnifyingGlass, ArrowUpRight, BookOpen, SignOut, CaretDown, Sun, Moon,
  TextAa, List, CheckCircle,
} from '@phosphor-icons/react';
import { AdminPages } from './AdminPages.jsx';
import { DashboardPages } from './DashboardPages.jsx';
import { Modal, Badge, Avatar, LangSwitch, useI18n } from './ui.jsx';
import { Brand } from './Brand.jsx';
import { api } from './api.js';
import { parseRoute } from './hashRoute.js';
import { t } from './i18n.js';

const adminNav = [
  ['users', 'navUsers', Users],
  ['admins', 'navAdmins', ShieldCheck],
  ['audit', 'navAudit', Clock],
  ['mail', 'navMail', Envelope],
  ['security', 'navSecurity', LockKey],
];
const userNav = [
  ['memories', 'navMemories', TreeStructure],
  ['diary', 'navDiary', BookOpen],
  ['sessions', 'navSessions', Desktop],
  ['keys', 'navKeys', Key],
  ['security', 'navSecurity', ShieldCheck],
];

function readRoute(admin, fallback) {
  const nav = admin ? adminNav : userNav;
  return parseRoute(location.hash, {
    admin,
    fallback,
    pageIds: nav.map((n) => n[0]),
  });
}

export function Shell({ admin, token, onLogout, onToken }) {
  useI18n();
  const fallback = admin ? 'users' : 'memories';
  const [route, setRoute] = useState(() => readRoute(admin, fallback));
  const page = route.page;
  const [modal, setModal] = useState(null);
  const [toast, setToast] = useState('');
  const [theme, setTheme] = useState('light');
  const [font, setFont] = useState('舒适'); // CSS selector value; labels are translated
  const [mobile, setMobile] = useState(false);
  const [me, setMe] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [keys, setKeys] = useState(null);
  const timer = useRef(null);

  function go(p) {
    location.hash = `/${p}`;
    setMobile(false);
  }
  function notify(text) {
    clearTimeout(timer.current);
    setToast(text);
    timer.current = setTimeout(() => setToast(''), 3500);
  }

  useEffect(() => {
    const fn = () => setRoute(readRoute(admin, fallback));
    window.addEventListener('hashchange', fn);
    if (!location.hash) location.hash = `#/${fallback}`;
    return () => {
      window.removeEventListener('hashchange', fn);
      clearTimeout(timer.current);
    };
  }, [admin, fallback]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.font = font;
    document.title = `${admin ? t('crumbAdmin') : t('crumbDash')} · respire`;
  }, [theme, font, admin]);

  const load = async () => {
    if (admin) {
      const info = await api('/admin/me', { token });
      setMe(info);
      return;
    }
    const info = await api('/api/self', { token });
    setMe(info);
    const [sess, k] = await Promise.all([
      api('/api/self/sessions', { token }),
      api('/api/self/keys', { token }),
    ]);
    setSessions(sess.sessions || []);
    setKeys(k);
  };
  useEffect(() => {
    load().catch((e) => {
      notify(e.message);
      if (e.status === 401 || e.status === 403) onLogout();
    });
  }, [token]);

  const visibleNav = admin
    ? adminNav.filter(([id]) => {
      if (!me) return true;
      if ((id === 'admins' || id === 'mail') && !(me.role === 'owner' || me.role === 'admin')) return false;
      return true;
    })
    : userNav;

  return (
    <>
      <a className="skip-link" href="#main-content">{t('mainNav')}</a>
      <div className={`console-layout ${admin ? 'admin-console' : 'user-console'}`}>
        <button className={`mobile-scrim ${mobile ? 'show' : ''}`} aria-label={t('closeNav')} onClick={() => setMobile(false)} />
        <aside className={`console-sidebar ${mobile ? 'open' : ''}`}>
          <div className="sidebar-heading"><Brand href={`#/${fallback}`} light /></div>
          <div className="workspace-switch">
            <Avatar name={me?.user || '?'} color="sand" />
            <div><strong>{me?.user || t('account')}</strong><span>{admin ? t('adminRoleSide', { role: me?.role || '' }) : t('personalAccount')}</span></div>
            <Badge>{admin ? t('adminSide') : t('personal')}</Badge>
          </div>
          <div className="nav-label">{admin ? t('navLabelAdmin') : t('navLabelUser')}</div>
          <nav aria-label={t('mainNav')}>
            {visibleNav.map(([id, labelKey, I]) => (
              <a key={id} href={`#/${id}`} className={page === id ? 'active' : ''} aria-current={page === id ? 'page' : undefined} onClick={() => setMobile(false)}>
                <I size={19} weight="regular" /><span>{t(labelKey)}</span><CaretDown size={12} className="nav-arrow" />
              </a>
            ))}
          </nav>
          <div className="sidebar-bottom">
            <div className="sidebar-security"><ShieldCheck size={18} /><span>{admin ? t('trustAdminTitle') : t('trustUserTitle')}</span></div>
            <a className="sidebar-link" href="https://github.com/risense-ai/respire-docs" target="_blank" rel="noreferrer"><BookOpen size={18} />{t('docsHelp')}<ArrowUpRight size={15} /></a>
            <button className="sidebar-link" onClick={onLogout}><SignOut size={18} />{t('signOut')}</button>
          </div>
        </aside>
        <div className="console-body">
          <header className="console-header">
            <button className="icon-button mobile-menu" aria-label={t('openNav')} onClick={() => setMobile(true)}><List size={23} /></button>
            <div className="breadcrumbs"><span>{admin ? t('crumbAdmin') : t('crumbDash')}</span><CaretDown size={13} className="crumb-arrow" /><strong>{t(visibleNav.find((n) => n[0] === page)?.[1] || 'navMemories')}</strong></div>
            <div className="top-actions">
              <LangSwitch />
              <button className="icon-button" aria-label={t('readingAppearance')} onClick={() => setModal({
                title: t('readingAppearance'), icon: TextAa,
                fields: [
                  { name: 'font', label: t('fontSize'), value: font, options: [{ value: '舒适', label: t('fontComfort') }, { value: '更大', label: t('fontLarger') }] },
                  { name: 'theme', label: t('appearance'), value: theme, options: [{ value: 'light', label: t('themeLight') }, { value: 'dark', label: t('themeDark') }] },
                ], submit: t('applySettings'),
                onSubmit: (v) => { setFont(v.font); setTheme(v.theme); notify(t('readingApplied')); },
              })}><TextAa size={20} /></button>
              <button className="icon-button" aria-label={t('toggleTheme')} onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>{theme === 'light' ? <Moon size={19} /> : <Sun size={19} />}</button>
              <button className="account-button" aria-label={t('accountMenu')} onClick={() => setModal({
                title: me?.user || t('account'),
                body: <div className="quick-links"><button type="button" onClick={() => { go('security'); setModal(null); }}><ShieldCheck size={21} />{t('navSecurity')}<ArrowUpRight size={16} /></button><button type="button" onClick={() => { setModal(null); onLogout(); }}><SignOut size={21} />{t('signOut')}</button></div>,
                submit: t('close'),
              })}><Avatar name={me?.user || '?'} color="sand" /></button>
            </div>
          </header>
          <main className={`console-main surface-${page}`} id="main-content" tabIndex={-1}>
            {admin ? (
              <AdminPages page={page} token={token} me={me} notify={notify} open={setModal} onReloadMe={load} />
            ) : (
              <DashboardPages page={page} memoryId={route.memoryId} token={token} me={me} sessions={sessions} keys={keys} notify={notify} open={setModal} go={go} onReload={load} onToken={onToken} onLogout={onLogout} />
            )}
          </main>
          <footer className="console-footer"><span>Respire <span>/</span> {admin ? t('crumbAdmin') : t('crumbDash')}</span><span>{me?.user}</span></footer>
        </div>
      </div>
      {modal && <Modal key={modal.title} config={modal} onClose={() => setModal(null)} />}
      <div className={`toast ${toast ? 'visible' : ''}`} role="status"><CheckCircle size={19} />{toast}</div>
    </>
  );
}