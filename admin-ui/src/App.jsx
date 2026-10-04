import { useEffect, useState } from 'react';
import { Gate } from './Gate.jsx';
import { Shell } from './Shell.jsx';
import {
  ADMIN_KEY, USER_KEY, api, onUnauthorized, readToken, writeSecret, writeSuper, writeToken,
} from './api.js';
import { pathRestToHash } from './hashRoute.js';
import { t } from './i18n.js';
import { useI18n } from './ui.jsx';

function pagePath() {
  return window.location.pathname.replace(/\/+$/, '') || '/';
}

export default function App() {
  useI18n();
  const path = pagePath();
  if (path === '/admin' || path.startsWith('/admin/')) return <Console admin />;
  if (path === '/dashboard' || path.startsWith('/dashboard/')) return <Console admin={false} />;
  return (
    <div className="gate-page" style={{ padding: 48 }}>
      <h1>respire</h1>
      <p>{t('fallbackHint')}</p>
    </div>
  );
}

function Console({ admin }) {
  useI18n();
  const key = admin ? ADMIN_KEY : USER_KEY;
  const [token, setTokenState] = useState(() => readToken(key));
  const [hint, setHint] = useState('');
  const [checked, setChecked] = useState(!readToken(key));
  const setToken = (value, superPass, secretKey) => {
    writeToken(key, value);
    if (superPass) writeSuper(superPass);
    if (secretKey) writeSecret(secretKey);
    setTokenState(value);
  };
  useEffect(() => {
    const path = pagePath();
    if (admin && path.startsWith('/admin/')) {
      window.history.replaceState(null, '', `/admin${pathRestToHash(path.slice('/admin/'.length))}`);
    }
    if (!admin && path.startsWith('/dashboard/')) {
      window.history.replaceState(null, '', `/dashboard${pathRestToHash(path.slice('/dashboard/'.length))}`);
    }
  }, [admin]);
  useEffect(() => {
    onUnauthorized((apiPath, requestToken) => {
      if (requestToken !== readToken(key)) return;
      if (admin && apiPath.startsWith('/admin') && !apiPath.startsWith('/admin/login')) setToken('');
      if (!admin && (apiPath.startsWith('/api/self') || apiPath === '/count' || apiPath === '/pull' || apiPath === '/login')) setToken('');
    });
  }, [admin]);
  useEffect(() => {
    if (!token) {
      setChecked(true);
      return;
    }
    const probe = admin ? '/admin/me' : '/api/self';
    api(probe, { token })
      .then(() => {
        if (readToken(key) === token) setChecked(true);
      })
      .catch((err) => {
        if (readToken(key) !== token) return;
        if (err.status === 401 || err.status === 403) setToken('');
        setChecked(true);
      });
  }, [admin, token]);
  if (!checked) {
    return <div className="gate-page" style={{ padding: 48 }}><p>{t('checkingLogin')}</p></div>;
  }
  if (!token) {
    return (
      <>
        <Gate
          admin={admin}
          notify={(t) => { setHint(t); window.setTimeout(() => setHint(''), 3500); }}
          onEnter={({ token: t, superPass, secretKey }) => setToken(t, superPass, secretKey)}
        />
        <div className={`toast ${hint ? 'visible' : ''}`} role="status">{hint}</div>
      </>
    );
  }
  return (
    <Shell
      admin={admin}
      token={token}
      onToken={(t) => setToken(t)}
      onLogout={() => setToken('')}
    />
  );
}
