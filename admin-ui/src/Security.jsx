import { useState } from 'react';
import { ShieldCheck, LockKey, Envelope, Shield, Trash } from '@phosphor-icons/react';
import { Button, Badge, Heading, Note, openPurgeConfirm, useI18n } from './ui.jsx';
import { authPayload } from './crypto.js';
import { api } from './api.js';
import { t } from './i18n.js';

export function Security({ admin, token, me, notify, onReload, open, onLogout }) {
  useI18n();
  const [tab, setTab] = useState('overview');
  const [error, setError] = useState('');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [email, setEmail] = useState(me?.email || '');
  const [emailCode, setEmailCode] = useState('');
  const [emailSent, setEmailSent] = useState(false);
  const [emailBusy, setEmailBusy] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const totp = !!me?.totp;

  const passPath = admin ? '/admin/password' : '/api/self/password';
  const totpBegin = admin ? '/admin/totp/begin' : '/api/self/totp/begin';
  const totpConfirm = admin ? '/admin/totp/confirm' : '/api/self/totp/confirm';
  const totpDisable = admin ? '/admin/totp/disable' : '/api/self/totp/disable';

  return (
    <>
      <Heading
        eyebrow={admin ? 'ADMINISTRATION / SECURITY' : 'YOUR ACCOUNT / SECURITY'}
        title={admin ? t('secTitleAdmin') : t('secTitleUser')}
        description={t('secDesc')}
      />
      <div className="security-overview">
        <div className="large-mark"><ShieldCheck size={35} /></div>
        <div>
          <h2>{totp ? t('totpOnH2') : t('totpOffH2')}</h2>
          <p>{totp ? t('totpOnP') : t('totpOffP')}</p>
        </div>
        <Badge tone={totp ? 'green' : 'amber'}>{totp ? t('protectedOn') : t('suggestTotp')}</Badge>
      </div>
      <div className="tabs security-tabs">
        {[['overview', t('overview')], ['pass', t('loginPassH3')], ...(!admin ? [['mail', t('bindEmail')]] : []), ['totp', t('twoFactor')]].map(([id, label]) => (
          <button className={tab === id ? 'active' : ''} key={id} onClick={() => { setTab(id); setError(''); }}>{label}</button>
        ))}
      </div>
      {tab === 'overview' ? (
        <section className="panel settings-panel">
          <div className="setting-row">
            <LockKey size={25} />
            <div><h3>{t('loginPassH3')}</h3><p>{t('loginPassP')}</p></div>
            <Button onClick={() => setTab('pass')}>{t('changePassword')}</Button>
          </div>
          {!admin && (
            <div className="setting-row">
              <Envelope size={25} />
              <div><h3>{t('recoveryEmail')} {me?.email_verified ? <Badge tone="green">{t('verified')}</Badge> : <Badge>{t(me?.email ? 'unverified' : 'unbound')}</Badge>}</h3><p>{me?.email || t('notBound')}</p></div>
              <Button onClick={() => setTab('mail')}>{t('bindEmail')}</Button>
            </div>
          )}
          <div className="setting-row">
            <Shield size={25} />
            <div><h3>{t('totpH3')} <Badge tone={totp ? 'green' : 'neutral'}>{totp ? t('totpOn') : t('totpOff')}</Badge></h3><p>{t('totpP')}</p></div>
            <Button onClick={() => setTab('totp')}>{t('manage')}</Button>
          </div>
        </section>
      ) : tab === 'pass' ? (
        <section className="panel form-panel">
          <h2>{t('updateLoginPass')}</h2>
          <p>{t('updateLoginPassP')}</p>
          <form onSubmit={async (e) => {
            e.preventDefault();
            if (password !== confirmation) return setError(t('passMismatch'));
            if (admin && me?.kind !== 'super_admin') return setError(t('envAdminNoPass'));
            try {
              const payload = await authPayload(me.user, password);
              await api(passPath, { method: 'POST', token, body: { pass_hash: payload.pass_hash, salt: payload.salt } });
              setPassword(''); setConfirmation(''); setError('');
              notify(t('passUpdated'));
            } catch (err) {
              setError(err.message);
            }
          }}>
            <label className="field">{t('newLoginPassword')}<input type="password" required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" /></label>
            <label className="field">{t('confirmNewPass')}<input type="password" required value={confirmation} onChange={(e) => setConfirmation(e.target.value)} autoComplete="new-password" /></label>
            {error && <p className="form-error" role="alert">{error}</p>}
            <Button primary type="submit">{t('updatePass')}</Button>
          </form>
        </section>
      ) : tab === 'mail' ? (
        <section className="panel form-panel">
          <h2>{t('bindRecoveryEmail')}</h2>
          <p>{t('currentEmail', { email: me?.email || t('unbound') })}</p>
          <form onSubmit={async (e) => {
            e.preventDefault();
            if (emailBusy) return;
            setEmailBusy(true);
            setError('');
            try {
              if (!emailSent) {
                await api('/api/self/email', { method: 'POST', token, body: { email } });
                setEmailSent(true);
                notify(t('codeSent'));
                return;
              }
              await api('/api/self/email/confirm', { method: 'POST', token, body: { code: emailCode } });
              await onReload?.();
              notify(t('emailBound'));
              setEmailSent(false);
              setEmailCode('');
            } catch (err) {
              setError(err.message);
            } finally {
              setEmailBusy(false);
            }
          }}>
            <label className="field">{t('emailAddress')}<input type="email" required disabled={emailBusy} value={email} onChange={(e) => { setEmail(e.target.value); setEmailSent(false); setEmailCode(''); setError(''); }} /></label>
            {emailSent && <label className="field">{t('emailCode')}<input required inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} value={emailCode} onChange={(e) => setEmailCode(e.target.value)} /></label>}
            {error && <p className="form-error" role="alert">{error}</p>}
            <Button primary disabled={emailBusy}>{emailSent ? t('verifyAndBind') : t('sendCode')}</Button>
            {emailSent && <Button type="button" disabled={emailBusy} onClick={async () => {
              setEmailBusy(true); setError('');
              try {
                await api('/api/self/email', { method: 'POST', token, body: { email } });
                setEmailCode(''); notify(t('codeSent'));
              } catch (err) { setError(err.message); }
              finally { setEmailBusy(false); }
            }}>{t('resendCode')}</Button>}
          </form>
        </section>
      ) : (
        <section className="panel form-panel">
          <div className="feature-mark"><ShieldCheck size={30} /></div>
          <h2>{t('totpTitle')}</h2>
          <p>{t('totpApps')}</p>
          <div className="row" style={{ gap: 8, marginBottom: 16 }}>
            <Button onClick={async () => {
              try {
                const r = await api(totpBegin, { method: 'POST', token });
                setTotpSecret(r.secret);
              } catch (err) { setError(err.message); }
            }}>{t('startBind')}</Button>
          </div>
          {totpSecret ? <div className="setup-key"><code>{totpSecret}</code></div> : null}
          <label className="field">{t('verify')}<input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} /></label>
          {error && <p className="form-error" role="alert">{error}</p>}
          <div className="key-actions">
            <Button primary onClick={async () => {
              try {
                await api(totpConfirm, { method: 'POST', token, body: { code: totpCode } });
                await onReload?.();
                notify(t('totpOnOk'));
                setError('');
                setTotpSecret('');
                setTotpCode('');
              } catch (err) { setError(err.message); }
            }}>{t('confirmOn')}</Button>
            <Button danger onClick={async () => {
              try {
                await api(totpDisable, { method: 'POST', token, body: { code: totpCode } });
                await onReload?.();
                notify(t('totpOffOk'));
                setError('');
                setTotpSecret('');
                setTotpCode('');
              } catch (err) { setError(err.message); }
            }}>{t('close')}</Button>
          </div>
        </section>
      )}
      <div className="below-note"><ShieldCheck size={18} />{t('credsIndependent')}</div>
      {!admin && open && me?.user ? (
        <section className="purge-zone">
          <div>
            <h3>{t('purgeAccount')}</h3>
            <p>{t('purgeAccountP')}</p>
          </div>
          <Button danger className="purge" icon={Trash} onClick={() => openPurgeConfirm({
            open,
            user: me?.user,
            onConfirm: async () => {
              await api('/api/self/purge', { method: 'POST', token, body: { confirm: me?.user } });
              notify(t('purged'));
              onLogout?.();
            },
          })}>{t('purge')}</Button>
        </section>
      ) : null}
    </>
  );
}
