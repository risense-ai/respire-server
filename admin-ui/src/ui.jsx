import React, { useEffect, useRef, useState } from 'react';
import { X, Check, ArrowUpRight, ShieldCheck, Copy, WarningCircle, Info, ArrowRight, Trash } from '@phosphor-icons/react';
import { t, setLocale as setUiLocale, getLocale, subscribeLocale } from './i18n.js';

export function useI18n() {
  const [locale, setLoc] = useState(getLocale());
  useEffect(() => subscribeLocale(setLoc), []);
  return { locale, t, setLocale: setUiLocale };
}

export function LangSwitch() {
  const { locale, setLocale } = useI18n();
  return (
    <div className="lang-switch" role="group" aria-label={t('language')}>
      <button type="button" aria-pressed={locale === 'en'} onClick={() => setLocale('en')}>EN</button>
      <button type="button" aria-pressed={locale === 'zh'} onClick={() => setLocale('zh')}>中文</button>
    </div>
  );
}
export const Icon = ({
  as: C,
  size = 20,
  ...props
}) => <C size={size} weight="regular" {...props} />;
export const Button = ({
  children,
  icon: I,
  primary,
  danger,
  className = '',
  ...p
}) => <button className={`button ${primary ? 'primary' : ''} ${danger ? 'danger' : ''} ${className}`} {...p}>{I && <I size={19} />} {children}</button>;
export const Badge = ({
  children,
  tone = 'neutral'
}) => <span className={`badge ${tone}`}>{children}</span>;
export const Avatar = ({
  name,
  color = 'purple',
  large
}) => <span className={`avatar ${color} ${large ? 'large' : ''}`}>{name?.slice(0, 1)}</span>;
export function Heading({
  eyebrow,
  title,
  description,
  children
}) {
  return <div className="page-heading"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{children && <div className="heading-actions">{children}</div>}</div>;
}
export function Empty({
  title,
  text,
  children
}) {
  title = title ?? t('emptyTitle');
  text = text ?? t('emptyText');
  return <div className="empty"><Info size={34} /><h3>{title}</h3><p>{text}</p>{children}</div>;
}
export function Toggle({
  label,
  checked,
  onChange
}) {
  return <button className={`switch ${checked ? 'on' : ''}`} role="switch" aria-label={label} aria-checked={checked} onClick={() => onChange(!checked)}><span /></button>;
}
export function Note({
  children,
  tone = '',
  icon: I = ShieldCheck
}) {
  return <div className={`note ${tone}`}><I size={20} /><span>{children}</span></div>;
}
export function download(name, text, type = 'text/plain;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([text], {
    type
  }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
export async function copy(text, notify) {
  try {
    await navigator.clipboard.writeText(text);
    notify(t('copied'));
  } catch {
    notify(t('copyBlocked'));
  }
}
export function Modal({
  config,
  onClose
}) {
  const ref = useRef(null);
  const optionValue = option => Array.isArray(option) ? option[0] : option?.value ?? option;
  const optionLabel = option => Array.isArray(option) ? option[1] : option?.label ?? option;
  const [values, setValues] = useState(Object.fromEntries((config.fields || []).map(f => [f.name, f.value ?? (f.options?.length ? optionValue(f.options[0]) : '')])));
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const el = ref.current;
    el.showModal();
    return () => el.close();
  }, []);
  async function submit(e) {
    e.preventDefault();
    setError('');
    const err = config.validate?.(values);
    if (err) {
      setError(err);
      return;
    }
    setBusy(true);
    try {
      const keep = await config.onSubmit?.(values);
      if (keep !== false) onClose();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return <dialog ref={ref} className={`modal ${config.wide ? 'wide' : ''} ${config.danger ? 'danger' : ''}`} onCancel={e => {
    e.preventDefault();
    onClose();
  }} onClick={e => {
    if (e.target === ref.current) onClose();
  }}><form onSubmit={submit}><div className="modal-heading"><div className="modal-mark">{config.icon ? React.createElement(config.icon, {
            size: 26
          }) : <ShieldCheck size={26} />}</div><button type="button" className="icon-button" aria-label={t('closeDialog')} onClick={onClose}><X size={22} /></button></div><h2>{config.title}</h2>{config.description && <p className="modal-description">{config.description}</p>}{config.body}{config.fields?.map(f => <label className="field" key={f.name}>{f.label}{f.options ? <select aria-label={f.label} value={values[f.name]} onChange={e => setValues({
          ...values,
          [f.name]: e.target.value
        })}>{f.options.map(o => <option key={optionValue(o)} value={optionValue(o)}>{optionLabel(o)}</option>)}</select> : f.type === 'textarea' ? <textarea aria-label={f.label} rows={f.rows || 6} required={f.required !== false} placeholder={f.placeholder} value={values[f.name]} onChange={e => setValues({
          ...values,
          [f.name]: e.target.value
        })} /> : <input aria-label={f.label} autoFocus={f.autofocus} type={f.type || 'text'} required={f.required !== false} placeholder={f.placeholder} value={values[f.name]} onChange={e => setValues({
          ...values,
          [f.name]: e.target.value
        })} autoComplete="off" minLength={f.minLength} />}{f.hint && <small>{f.hint}</small>}</label>)}{error && <p role="alert" className="form-error"><WarningCircle size={18} />{error}</p>}<div className="modal-footer"><Button type="button" onClick={onClose}>{config.cancel || t('cancel')}</Button><Button type="submit" primary={!config.danger} danger={config.danger} className={config.danger ? 'purge' : ''} disabled={busy}>{busy ? t('working') : config.submit || t('confirm')}</Button></div></form></dialog>;
}

/** Account purge requires two confirmations: explain the effects, then verify the username and confirmation phrase. */
export function openPurgeConfirm({ open, user, onConfirm }) {
  const phrase = t('purgePhrase');
  open({
    title: t('purgeTitle'),
    icon: WarningCircle,
    danger: true,
    description: t('purgeDesc', { user }),
    submit: t('purgeSubmit1'),
    onSubmit: async () => {
      window.setTimeout(() => open({
        title: t('purgeTitle2'),
        icon: Trash,
        danger: true,
        description: t('purgeDesc2'),
        fields: [
          { name: 'user', label: t('typeUsername', { user }), autofocus: true },
          { name: 'phrase', label: t('typePhrase') },
        ],
        validate: (v) => {
          if (v.user !== user) return t('userMismatch');
          if (v.phrase !== phrase) return t('pleaseTypePhrase');
          return null;
        },
        onSubmit: onConfirm,
        submit: t('purgeFinal'),
      }), 0);
    },
  });
}
export function SecretResult({
  title,
  description,
  value,
  notify
}) {
  return <div><p>{description}</p><div className="secret-result"><code>{value}</code><Button type="button" icon={Copy} onClick={() => copy(value, notify)}>{t('copy')}</Button></div><Note icon={Info}>{t('secretOnce')}</Note></div>;
}
