import { useState } from 'react';
import { ArrowRight, ShieldCheck, LockKey, Key } from '@phosphor-icons/react';
import { Button, Badge, Note, LangSwitch, useI18n } from './ui.jsx';
import { brandLogo } from './brand.js';
import { authPayload, generateSecretKey, wrapVaultV4 } from './crypto.js';
import { api, writeSecret } from './api.js';
import { t } from './i18n.js';

export function Gate({ admin, onEnter, notify }) {
  useI18n();
  const [tab, setTab] = useState('login');
  const [step, setStep] = useState(1);
  const [user, setUser] = useState(admin ? 'admin' : '');
  const [pass, setPass] = useState('');
  const [confirm, setConfirm] = useState('');
  const [superpass, setSuper] = useState('');
  const [superconfirm, setSuperConfirm] = useState('');
  const [code, setCode] = useState('');
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState('');
  const [tokenMode, setTokenMode] = useState(false);
  const [envToken, setEnvToken] = useState('');
  const [ticket, setTicket] = useState('');
  const [busy, setBusy] = useState(false);
  const [issued, setIssued] = useState(null);

  const fail = (e) => setError(e.message || String(e));

  const finishUser = (token, superPass, secretKey) => {
    onEnter({ token, superPass, secretKey });
  };

  async function submit(e) {
    e.preventDefault();
    setError('');
    if (admin) {
      setBusy(true);
      try {
        if (envToken.trim()) {
          await api('/admin/me', { token: envToken.trim() });
          onEnter({ token: envToken.trim() });
          return;
        }
        if (ticket) {
          const reply = await api('/admin/login/totp', { method: 'POST', body: { ticket, code } });
          if (reply.totp_required) {
            setTicket(reply.ticket);
            notify(t('needTotp'));
            return;
          }
          onEnter({ token: reply.token });
          return;
        }
        const payload = await authPayload(user, pass);
        const reply = await api('/admin/login', { method: 'POST', body: { user: payload.user, pass_hash: payload.pass_hash } });
        if (reply.totp_required) {
          setTicket(reply.ticket);
          notify(t('needTotp'));
          return;
        }
        onEnter({ token: reply.token });
      } catch (err) {
        fail(err);
      } finally {
        setBusy(false);
      }
      return;
    }

    if (tab === 'register') {
      if (step === 1) {
        if (pass !== confirm) return setError(t('passMismatch'));
        setStep(2);
        return;
      }
      if (step === 2) {
        setBusy(true);
        try {
          const payload = await authPayload(user, pass);
          const reply = await api('/register', { method: 'POST', body: { ...payload, device_name: 'dashboard' } });
          // v4 uses a generated A3- recovery code as the single memory unlock factor.
          const superPass = generateSecretKey();
          const vault = await wrapVaultV4(superPass);
          await api('/api/self/vault', { method: 'POST', token: reply.token, body: vault });
          // Store under the same localStorage key used by api.js SUPER_KEY.
          try { localStorage.setItem('onememory.superPass', superPass); } catch {}
          try { localStorage.setItem('onememory.superPassAt', String(Date.now())); } catch {}
          try { localStorage.removeItem('onememory.secretKey'); } catch {}
          setIssued({ token: reply.token, superPass });
          setStep(3);
        } catch (err) {
          fail(err);
        } finally {
          setBusy(false);
        }
        return;
      }
      if (!saved) return setError(t('confirmSuperFirst'));
      finishUser(issued.token, issued.superPass, undefined);
      notify(t('accountCreated'));
      return;
    }

    if (tab === 'reset') {
      if (step === 1) {
        setBusy(true);
        try {
          await api('/forgot', { method: 'POST', body: { user } });
          notify(t('resetQueued'));
          setStep(2);
        } catch (err) {
          fail(err);
        } finally {
          setBusy(false);
        }
        return;
      }
      if (pass !== confirm) return setError(t('passMismatch'));
      setBusy(true);
      try {
        const payload = await authPayload(user, pass);
        await api('/reset', { method: 'POST', body: { user: payload.user, code, pass_hash: payload.pass_hash, salt: payload.salt } });
        notify(t('passwordReset'));
        setTab('login');
        setStep(1);
      } catch (err) {
        fail(err);
      } finally {
        setBusy(false);
      }
      return;
    }

    setBusy(true);
    try {
      if (ticket) {
        const reply = await api('/login/totp', { method: 'POST', body: { ticket, code, device_name: 'dashboard' } });
        finishUser(reply.token, superpass, undefined);
        return;
      }
      const payload = await authPayload(user, pass);
      const reply = await api('/login', { method: 'POST', body: { user: payload.user, pass_hash: payload.pass_hash, device_name: 'dashboard' } });
      if (reply.totp_required) {
        setTicket(reply.ticket);
        notify(t('needTotp'));
        return;
      }
      finishUser(reply.token, superpass, undefined);
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="gate-page">
      <header>
        <img src={brandLogo} alt="Respire" />
        <Badge>{admin ? t('badgeAdmin') : t('badgeUser')}</Badge>
        <LangSwitch />
      </header>
      <div className="gate-layout">
        <section className="gate-story">
          <span className="eyebrow">{admin ? t('gateAdminEyebrow') : t('gateUserEyebrow')}</span>
          <h1 style={{ whiteSpace: 'pre-line' }}>{admin ? t('gateAdminH1') : t('gateUserH1')}</h1>
          <p>{admin ? t('gateAdminLead') : t('gateUserLead')}</p>
          <div className="gate-principles">
            <div><ShieldCheck size={24} /><span>{t('principleEncrypt')}</span></div>
            <div><Key size={24} /><span>{t('principleKeys')}</span></div>
            <div><LockKey size={24} /><span>{t('principleCipher')}</span></div>
          </div>
        </section>
        <section className="gate-form panel">
          <div className="feature-mark">{admin ? <ShieldCheck size={28} /> : <LockKey size={28} />}</div>
          <h2>{admin ? t('gateAdminTitle') : tab === 'register' ? (step === 3 ? t('gateSaveRecovery') : t('gateCreate')) : tab === 'reset' ? t('gateResetTitle') : t('gateWelcome')}</h2>
          <p>{admin ? t('gateAdminLeadForm') : t('gateUserLeadForm')}</p>
          {!admin && step === 1 && (
            <div className="tabs stretch">
              {[['login', t('login')], ['register', t('register')]].map(([id, label]) => (
                <button key={id} className={tab === id ? 'active' : ''} onClick={() => { setTab(id); setError(''); setTicket(''); }}>{label}</button>
              ))}
            </div>
          )}
          {tab === 'register' && <div className="step-label">{step} / 2 · {[t('stepAccount'), t('stepSuper')][step - 1]}</div>}
          <form onSubmit={submit}>
            {tab === 'register' && step === 3 && issued ? (
              <>
                <Note tone="amber">{t('copySuperNow')}</Note>
                <div className="demo-key"><span>{t('superPassword')}</span><code>{issued.superPass}</code></div>
                <label className="check-label">
                  <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
                  {t('confirmSavedSuper')}
                </label>
              </>
            ) : tab === 'register' && step === 2 ? (
              <>
                <Note tone="amber">{t('clickGenerateSuper')}</Note>
              </>
            ) : (
              <>
                {admin && tokenMode ? (
                  <label className="field">{t('adminToken')}<input required type="password" value={envToken} onChange={(e) => setEnvToken(e.target.value)} /></label>
                ) : (
                  <>
                    <label className="field">{t('username')}<input required value={user} onChange={(e) => setUser(e.target.value)} placeholder={admin ? 'admin' : t('usernamePh')} autoComplete="username" /></label>
                    {(tab !== 'reset' || step === 2) && (
                      <label className="field">{tab === 'reset' && step === 2 ? t('newLoginPassword') : t('loginPassword')}
                        <input required type="password" minLength={tab === 'login' ? 1 : 8} value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="off" />
                      </label>
                    )}
                    {(tab === 'register' && step === 1) || (tab === 'reset' && step === 2) ? (
                      <label className="field">{t('confirmLoginPassword')}<input type="password" required value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
                    ) : null}
                    {tab === 'login' && !admin ? (
                      <label className="field">{t('superOptional')}<input type="password" value={superpass} onChange={(e) => setSuper(e.target.value)} autoComplete="off" /></label>
                    ) : null}
                    {ticket ? <label className="field">{t('totpCode')}<input required value={code} onChange={(e) => setCode(e.target.value)} /></label> : null}
                    {tab === 'reset' && step === 2 ? <label className="field">{t('emailCode')}<input value={code} required onChange={(e) => setCode(e.target.value)} /></label> : null}
                  </>
                )}
              </>
            )}
            {error && <p role="alert" className="form-error">{error}</p>}
            <Button primary type="submit" className="full" icon={ArrowRight} disabled={busy || (tab === 'register' && step === 3 && !saved)}>
              {tab === 'register' ? (step === 3 ? t('enterMemory') : step === 2 ? t('generateSuper') : t('continue')) : tab === 'reset' ? (step === 1 ? t('sendCode') : t('resetPassword')) : ticket ? t('verify') : t('login')}
            </Button>
          </form>
          {admin ? (
            <button className="gate-link" onClick={() => setTokenMode(!tokenMode)}>{tokenMode ? t('usePasswordLogin') : t('useAdminToken')}</button>
          ) : (
            <button className="gate-link" onClick={() => { setTab(tab === 'reset' ? 'login' : 'reset'); setStep(1); setError(''); setTicket(''); }}>
              {tab === 'reset' ? t('backToLogin') : t('forgotPassword')}
            </button>
          )}
        </section>
      </div>
      <footer>{t('footerBelong')}<span>{admin ? t('badgeAdmin') : t('badgeUser')}</span></footer>
    </div>
  );
}
