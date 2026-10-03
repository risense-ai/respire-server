import { useEffect, useRef, useState } from 'react';
import {
  UserPlus, MagnifyingGlass, DownloadSimple, CaretLeft, CaretRight,
  ShieldCheck, LockKey, X, Desktop, Prohibit, ArrowClockwise, Key, SignOut,
  Clock, Envelope, Trash, Shield, WarningCircle,
} from '@phosphor-icons/react';
import { Button, Badge, Avatar, Heading, Empty, Note, SecretResult, openPurgeConfirm, useI18n } from './ui.jsx';
import { brandLogo } from './brand.js';
import { authPayload } from './crypto.js';
import { api } from './api.js';
import { Security } from './Security.jsx';
import { t } from './i18n.js';

function statusOf(u) {
  if (u.deleted) return 'deleted';
  if (u.disabled) return 'banned';
  return 'ok';
}

function statusLabel(code) {
  if (code === 'deleted') return t('statusDeleted');
  if (code === 'banned') return t('statusBanned');
  return t('statusOk');
}

function colorOf(name) {
  const colors = ['sage', 'sand', 'purple', 'rose'];
  let h = 0;
  for (const c of name || '') h += c.charCodeAt(0);
  return colors[h % colors.length];
}

function auditType(action) {
  if (/管理员|admin/.test(action)) return 'admin';
  if (/会话|kick|token|签发/.test(action)) return 'session';
  if (/密码|totp|安全/.test(action)) return 'security';
  return 'user';
}

export function AdminPages({ page, token, me, notify, open, onReloadMe }) {
  useI18n();
  const [users, setUsers] = useState([]);
  const [total, setTotal] = useState(0);
  const [summary, setSummary] = useState(null);
  const pageSize = 50;
  const [pn, setPn] = useState(1);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [selected, setSelected] = useState(null);
  const [sessions, setSessions] = useState([]);
  const [detailTab, setDetailTab] = useState('account');
  const [admins, setAdmins] = useState([]);
  const [audit, setAudit] = useState([]);
  const [auditFilter, setAuditFilter] = useState('all');
  const [outbox, setOutbox] = useState([]);
  const [mail, setMail] = useState(null);
  const drawerRef = useRef(null);
  const canWrite = me && (me.role === 'owner' || me.role === 'admin');
  const isOwner = me?.role === 'owner';

  const loadUsers = async (p = pn, q = query, status = filter) => {
    const list = await api(`/admin/users?q=${encodeURIComponent(q)}&page=${p}&limit=${pageSize}&status=${status}`, { token });
    setUsers(list.users || []);
    setTotal(list.total || 0);
    setSummary(list.summary);
    setPn(list.page || p);
  };
  const loadAll = async () => {
    await loadUsers();
    if (canWrite) {
      const a = await api('/admin/admins', { token });
      setAdmins(a.admins || []);
      const m = await api('/admin/outbox', { token });
      const items = m.items || [];
      setOutbox(items);
      setMail((cur) => items.find((x) => x.id === cur?.id) || items[0] || null);
    }
    const au = await api('/admin/audit?page=1', { token });
    setAudit(au.items || []);
  };
  useEffect(() => {
    loadAll().catch((e) => {
      notify(e.message);
    });
  }, [token]);

  const pick = async (user) => {
    setSelected(user);
    setDetailTab('account');
    const reply = await api(`/admin/users/${encodeURIComponent(user)}/sessions`, { token });
    setSessions(reply.sessions || []);
  };

  useEffect(() => {
    if (!selected || page !== 'users') return;
    const handler = (e) => { if (e.key === 'Escape') setSelected(null); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [selected, page]);

  const shown = users;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const current = users.find((u) => u.user === selected);
  const counts = summary || {};

  const createUser = () => open({
    title: t('createUser'),
    icon: UserPlus,
    description: t('createUserDesc'),
    fields: [
      { name: 'id', label: t('username'), placeholder: t('usernameEg') },
      { name: 'pass', label: t('initialLoginPass'), type: 'password', minLength: 8, hint: t('atLeast8') },
      { name: 'email', label: t('emailOptional'), type: 'email', required: false },
    ],
    validate: (v) => (!v.id?.trim() ? t('needUsername') : null),
    onSubmit: async (v) => {
      const payload = await authPayload(v.id.trim(), v.pass);
      const reply = await api('/admin/users', { method: 'POST', token, body: { ...payload, email: v.email } });
      notify(t('userCreated'));
      open({
        title: t('issueSession'),
        body: <SecretResult value={reply.token} notify={notify} description={t('copyBeforeClose')} />,
        submit: t('done'),
      });
      await loadUsers(1, '');
    },
    submit: t('createUser'),
  });

  const exportUsers = async () => {
    const r = await api(`/admin/users?q=${encodeURIComponent(query)}&export=1`, { token });
    const blob = new Blob([r.csv], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'users.csv';
    a.click();
    notify(t('exportedUsers'));
  };

  if (page === 'users') {
    return (
      <>
        <Heading eyebrow="ADMINISTRATION / USERS" title={t('adminUsers')} description={t('adminUsersDesc')}>
          <Button icon={DownloadSimple} onClick={exportUsers}>{t('exportData')}</Button>
          {canWrite ? <Button icon={UserPlus} primary onClick={createUser}>{t('createUser')}</Button> : null}
        </Heading>
        <div className="metric-strip">
          <div><span>{t('allUsers')}</span><strong>{summary?.all ?? '—'}<small>{t('people')}</small></strong></div>
          <div><span>{t('pageOk')}</span><strong>{summary?.ok ?? '—'}</strong></div>
          <div><span>{t('activeSessions')}</span><strong>{summary?.sessions ?? '—'}<small>{t('unitGe')}</small></strong></div>
          <div><span>{t('cloudCipher')}</span><strong>{summary?.ciphertext?.toLocaleString() ?? '—'}<small>{t('unitTiao')}</small></strong></div>
        </div>
        <section className="panel table-panel">
          <div className="panel-toolbar">
            <div className="tabs" aria-label={t('userStatusFilter')}>
              {[['all', t('filterAll')], ['ok', t('statusOk')], ['banned', t('statusBanned')], ['deleted', t('statusDeleted')]].map(([id, label]) => (
                <button key={id} className={filter === id ? 'active' : ''} onClick={() => { setFilter(id); setSelected(null); loadUsers(1, query, id).catch((e) => notify(e.message)); }}>{label}<span>{counts[id] ?? '—'}</span></button>
              ))}
            </div>
            <div className="toolbar-controls">
              <label className="search-box">
                <MagnifyingGlass size={20} />
                <input aria-label={t('searchUser')} placeholder={t('searchUserPh')} value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') loadUsers(1, query); }} />
              </label>
            </div>
          </div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>{t('colUser')}</th><th>{t('colStatus')}</th><th>{t('colSessions')}</th><th>{t('colCipher')}</th><th>{t('colCreated')}</th><th /></tr></thead>
              <tbody>
                {shown.map((u) => (
                  <tr key={u.user} className={selected === u.user ? 'selected' : ''}>
                    <td>
                      <button className="user-cell" onClick={() => pick(u.user)}>
                        <Avatar name={u.user} color={colorOf(u.user)} />
                        <span><strong>{u.user}</strong><em>{u.email || t('noEmail')}</em></span>
                      </button>
                    </td>
                    <td><Badge tone={statusOf(u) === 'ok' ? 'green' : statusOf(u) === 'banned' ? 'amber' : 'neutral'}>{statusLabel(statusOf(u))}</Badge></td>
                    <td className="num">{u.session_count || 0}</td>
                    <td className="num">{(u.active || 0).toLocaleString()}<span className="dim">{t('unitTiao') ? ` ${t('unitTiao')}` : ''}</span></td>
                    <td className="dim nowrap">{u.created_at || '—'}</td>
                    <td><button className="icon-button" aria-label={t('viewUser', { user: u.user })} onClick={() => pick(u.user)}><CaretRight size={19} /></button></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!shown.length && <Empty />}
          </div>
          <div className="table-footer">
            <span>{t('totalUsers', { n: total, size: pageSize })}</span>
            <div>
              <button className="icon-button" aria-label={t('prevPage')} disabled={pn <= 1} onClick={() => loadUsers(pn - 1, query)}><CaretLeft size={19} /></button>
              <span>{pn} / {pages}</span>
              <button className="icon-button" aria-label={t('nextPage')} disabled={pn >= pages} onClick={() => loadUsers(pn + 1, query)}><CaretRight size={19} /></button>
            </div>
          </div>
        </section>
        <div className="below-note"><ShieldCheck size={19} />{t('adminNote')}</div>
        {current && (
          <div className="drawer-backdrop" onClick={() => setSelected(null)}>
            <aside ref={drawerRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label={t('userDetail')} className="drawer" onClick={(e) => e.stopPropagation()}>
              <div className="drawer-top"><span>{t('userDetail')}</span><button className="icon-button" aria-label={t('close')} onClick={() => setSelected(null)}><X size={23} /></button></div>
              <div className="profile-heading">
                <Avatar name={current.user} color={colorOf(current.user)} large />
                <h2>{current.user}</h2>
                <p>@{current.user}</p>
                <Badge tone={statusOf(current) === 'ok' ? 'green' : 'amber'}>{statusLabel(statusOf(current))}</Badge>
              </div>
              <div className="tabs stretch">
                {[['account', t('tabAccount')], ['devices', t('tabDevices')]].map(([id, label]) => (
                  <button key={id} className={detailTab === id ? 'active' : ''} onClick={() => setDetailTab(id)}>{label}</button>
                ))}
              </div>
              {detailTab === 'account' ? (
                <>
                  <dl className="details">
                    <div><dt>{t('emailAddr')}</dt><dd>{current.email || t('unbound')}</dd></div>
                    <div><dt>{t('colCreated')}</dt><dd>{current.created_at || '—'}</dd></div>
                    <div><dt>{t('colCipher')}</dt><dd>{t('nItems', { n: current.active || 0 })}</dd></div>
                    <div><dt>{t('mainToken')}</dt><dd><code>{current.token_masked || '—'}</code></dd></div>
                  </dl>
                  <Note>{t('adminCannotRead')}</Note>
                  {canWrite ? (
                    <div className="action-list">
                      <button onClick={async () => {
                        const reply = await api(`/admin/users/${encodeURIComponent(current.user)}/sessions`, { method: 'POST', token, body: { device_name: 'admin' } });
                        notify(t('issuedSession'));
                        open({ title: t('sessionTokenTitle'), body: <SecretResult value={reply.token} notify={notify} description={t('copyCloseShort')} />, submit: t('done') });
                        pick(current.user); loadUsers(pn, query);
                      }} disabled={statusOf(current) !== 'ok'}><Key size={20} />{t('issueSession')}<CaretRight size={18} /></button>
                      <button onClick={() => open({
                        title: t('resetLoginPass'),
                        description: t('resetLoginPassDesc', { user: current.user }),
                        fields: [{ name: 'pass', label: t('newPass'), type: 'password', minLength: 8 }, { name: 'confirm', label: t('confirmNewPass'), type: 'password' }],
                        validate: (v) => (v.pass !== v.confirm ? t('passMismatch') : null),
                        onSubmit: async (v) => {
                          const payload = await authPayload(current.user, v.pass);
                          await api(`/admin/users/${encodeURIComponent(current.user)}/update`, { method: 'POST', token, body: { pass_hash: payload.pass_hash, salt: payload.salt } });
                          notify(t('passUpdated'));
                        },
                        submit: t('updatePass'),
                      })}><LockKey size={20} />{t('resetLoginPass')}<CaretRight size={18} /></button>
                      <button onClick={async () => {
                        await api(`/admin/users/${encodeURIComponent(current.user)}/kick`, { method: 'POST', token });
                        notify(t('kicked'));
                        pick(current.user); loadUsers(pn, query);
                      }}><SignOut size={20} />{t('revokeAllSessions')}<CaretRight size={18} /></button>
                      <button disabled={statusOf(current) === 'deleted'} onClick={async () => {
                        await api(`/admin/users/${encodeURIComponent(current.user)}/update`, { method: 'POST', token, body: { disabled: !current.disabled } });
                        notify(current.disabled ? t('enabled') : t('disabled'));
                        loadUsers(pn, query); pick(current.user);
                      }}><Prohibit size={20} />{current.disabled ? t('unban') : t('banUser')}<CaretRight size={18} /></button>
                    </div>
                  ) : null}
                  {canWrite ? (
                    <div className="purge-actions">
                      {current.deleted ? (
                        <Button onClick={async () => {
                          await api(`/admin/users/${encodeURIComponent(current.user)}/restore`, { method: 'POST', token });
                          notify(t('restored')); loadUsers(pn, query); pick(current.user);
                        }} icon={ArrowClockwise}>{t('restoreUser')}</Button>
                      ) : (
                        <Button danger icon={Trash} onClick={() => open({
                          title: t('deleteUser'),
                          description: t('deleteUserDesc'),
                          fields: [{ name: 'confirm', label: t('typeUser', { user: current.user }) }],
                          validate: (v) => (v.confirm !== current.user ? t('usernameMismatch') : null),
                          onSubmit: async () => {
                            await api(`/admin/users/${encodeURIComponent(current.user)}/delete`, { method: 'POST', token });
                            notify(t('softDeleted'));
                            setSelected(null);
                            loadUsers(pn, query);
                          },
                          submit: t('confirmDelete'),
                          danger: true,
                        })}>{t('deleteUser')}</Button>
                      )}
                      <Button danger className="purge" icon={Trash} onClick={() => openPurgeConfirm({
                        open,
                        user: current.user,
                        onConfirm: async () => {
                          await api(`/admin/users/${encodeURIComponent(current.user)}/purge`, { method: 'POST', token });
                          notify(t('purgedFreed'));
                          setSelected(null);
                          loadUsers(pn, query);
                        },
                      })}>{t('purge')}</Button>
                    </div>
                  ) : null}
                </>
              ) : (
                <>
                  <p className="section-caption">{t('nActiveSessionsCaption', { n: sessions.length })}</p>
                  {sessions.map((s) => (
                    <div className="device-row" key={s.id}>
                      <Desktop size={24} />
                      <div><strong>{s.device_name}</strong><small>{s.created_at}</small></div>
                      {canWrite ? <button className="text-button danger" onClick={async () => {
                        await api(`/admin/users/${encodeURIComponent(current.user)}/sessions/${s.id}/revoke`, { method: 'POST', token });
                        pick(current.user);
                      }}>{t('revoke')}</button> : null}
                    </div>
                  ))}
                  {!sessions.length && <Empty title={t('noActiveSessions')} text={t('noActiveSessionsHint')} />}
                </>
              )}
            </aside>
          </div>
        )}
      </>
    );
  }

  if (page === 'admins') {
    return (
      <>
        <Heading eyebrow="ADMINISTRATION / ACCESS" title={t('adminsTitle')} description={t('adminsDesc')}>
          {isOwner ? <Button primary icon={UserPlus} onClick={() => open({
            title: t('addAdmin'),
            fields: [
              { name: 'id', label: t('username') },
              { name: 'pass', label: t('initialPass'), type: 'password', minLength: 8 },
              { name: 'role', label: t('roleLabel'), value: 'admin', options: [
                { value: 'viewer', label: t('roleViewerOpt') },
                { value: 'admin', label: t('roleAdminOpt') },
                { value: 'owner', label: t('roleOwnerOpt') },
              ] },
            ],
            onSubmit: async (v) => {
              const payload = await authPayload(v.id, v.pass);
              await api('/admin/admins', { method: 'POST', token, body: { ...payload, role: v.role } });
              notify(t('adminAdded'));
              loadAll();
            },
            submit: t('addAdmin'),
          })}>{t('addAdmin')}</Button> : null}
        </Heading>
        <div className="role-summary">
          {[['owner', t('roleOwnerOpt'), t('ownerRoleDesc')], ['admin', t('roleAdminOpt'), t('adminRoleDesc')], ['viewer', t('roleViewerOpt'), t('viewerRoleDesc')]].map(([r, name, d]) => (
            <div key={r}><Shield size={23} /><strong>{name}<small>{r}</small></strong><p>{d}</p></div>
          ))}
        </div>
        <section className="panel">
          <div className="section-top"><h2>{t('adminTeam')} <span>{admins.length}</span></h2><Badge>{t('currentIdentity', { role: me?.role })}</Badge></div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>{t('colAdmin')}</th><th>{t('colRole')}</th><th>{t('colTotp')}</th><th>{t('colStatus')}</th><th /></tr></thead>
              <tbody>
                {admins.map((a) => (
                  <tr key={a.user}>
                    <td><div className="user-cell"><Avatar name={a.user} /><span><strong>{a.user}</strong><em>{a.user === me?.user ? t('currentAccount') : a.role}</em></span></div></td>
                    <td><Badge tone={a.role === 'owner' ? 'purple' : 'neutral'}>{a.role}</Badge></td>
                    <td>{a.totp ? <span className="green-text"><ShieldCheck size={18} />{t('totpOn')}</span> : <span className="dim">{t('totpOff')}</span>}</td>
                    <td>{a.disabled ? t('disabled') : t('statusOk')}</td>
                    <td>{isOwner && a.user !== me?.user ? <Button danger onClick={async () => {
                      await api(`/admin/admins/${encodeURIComponent(a.user)}/revoke`, { method: 'POST', token });
                      notify(t('adminRemoved')); loadAll();
                    }}>{t('remove')}</Button> : <LockKey size={18} className="dim" />}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  }

  if (page === 'audit') {
    const rows = audit.filter((a) => auditFilter === 'all' || auditType(a.action) === auditFilter);
    return (
      <>
        <Heading eyebrow="ADMINISTRATION / ACTIVITY" title={t('auditTitle')} description={t('auditDesc')} />
        <section className="panel">
          <div className="panel-toolbar">
            <div className="tabs">{[['all', t('auditAll')], ['user', t('auditUser')], ['session', t('auditSession')], ['security', t('auditSecurity')], ['admin', t('auditAdmin')]].map(([id, label]) => (
              <button key={id} className={auditFilter === id ? 'active' : ''} onClick={() => setAuditFilter(id)}>{label}</button>
            ))}</div>
          </div>
          <div className="table-scroll">
            <table>
              <thead><tr><th>{t('colTime')}</th><th>{t('colActor')}</th><th>{t('colAction')}</th><th>{t('colTarget')}</th></tr></thead>
              <tbody>
                {rows.map((a) => (
                  <tr key={a.id}>
                    <td className="dim nowrap">{a.at}</td>
                    <td><span className="actor"><Avatar name={a.actor} />{a.actor}</span></td>
                    <td>{a.action}</td>
                    <td><code>{a.target}</code></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </>
    );
  }

  if (page === 'mail') {
    return (
      <>
        <Heading eyebrow="ADMINISTRATION / OUTBOX" title={t('mailTitle')} description={t('mailDesc')} />
        <section className="mail-layout panel">
          <div className="mail-list">
            <div className="section-top"><h2>{t('pendingMail')}</h2><Badge>{outbox.length}</Badge></div>
            {outbox.map((m) => (
              <button key={m.id} className={mail?.id === m.id ? 'selected' : ''} onClick={() => setMail(m)}>
                <Envelope size={23} />
                <div><strong>{m.subject}</strong><p>{m.to}</p><small>{m.at}</small></div>
                <CaretRight size={17} />
              </button>
            ))}
            {!outbox.length && <Empty title={t('queueEmpty')} text={t('noCodeMail')} />}
          </div>
          {mail ? (
            <article className="mail-preview">
              <Badge tone="purple">{mail.status}</Badge>
              <h2>{mail.subject}</h2>
              <p className="dim">{t('sentTo', { to: mail.to })}<br />{mail.at}</p>
              <hr />
              <img src={brandLogo} alt="Respire" />
              <p>{t('mailAttempts', { count: mail.attempts })}</p>
              {mail.last_error && <p>{mail.last_error}</p>}
              <p className="dim">{t('resetNotDecrypt')}</p>
            </article>
          ) : <article className="mail-preview"><Empty /></article>}
        </section>
      </>
    );
  }

  return <Security admin token={token} me={me} notify={notify} onReload={onReloadMe} />;
}
