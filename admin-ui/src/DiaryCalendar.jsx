import { useMemo, useState } from 'react';
import { Article, X, CaretLeft, CaretRight } from '@phosphor-icons/react';
import { t } from './i18n.js';
import { useI18n } from './ui.jsx';

// The monthly diary shows entry counts; selecting a date opens its entries.
// Use local YYYY-MM-DD dates to match CLI diary titles.
const WEEK_KEYS = ['weekMon', 'weekTue', 'weekWed', 'weekThu', 'weekFri', 'weekSat', 'weekSun'];
const pad2 = value => String(value).padStart(2, '0');
const keyOf = (year, month, day) => `${year}-${pad2(month + 1)}-${pad2(day)}`;

export default function DiaryCalendar({ days = [], onOpenMemory }) {
  useI18n();
  const byDay = useMemo(() => new Map(days.map(item => [item.day, item])), [days]);
  const today = useMemo(() => {
    const now = new Date();
    return keyOf(now.getFullYear(), now.getMonth(), now.getDate());
  }, []);
  // days arrives in descending date order; default to the newest date.
  const anchor = days[0]?.day || today;
  const [cursor, setCursor] = useState(() => {
    const [year, month] = anchor.split('-').map(Number);
    return { y: year, m: (month || 1) - 1 };
  });
  const [detail, setDetail] = useState(null);

  const cells = useMemo(() => {
    const first = new Date(cursor.y, cursor.m, 1);
    const lead = (first.getDay() + 6) % 7; // Monday is the first weekday column
    const total = new Date(cursor.y, cursor.m + 1, 0).getDate();
    const list = Array.from({ length: lead }, () => null);
    for (let day = 1; day <= total; day += 1) list.push({ day: keyOf(cursor.y, cursor.m, day), label: day });
    return list;
  }, [cursor]);

  const monthCount = useMemo(
    () => cells.reduce((sum, cell) => sum + (cell ? (byDay.get(cell.day)?.items.length || 0) : 0), 0),
    [cells, byDay],
  );
  const shiftMonth = delta => setCursor(({ y, m }) => {
    const next = m + delta;
    return { y: y + Math.floor(next / 12), m: ((next % 12) + 12) % 12 };
  });
  const jumpToday = () => {
    const now = new Date();
    setCursor({ y: now.getFullYear(), m: now.getMonth() });
  };

  return <section className="om-diary" aria-label={t('diaryAria')}>
    <header className="om-diary-bar">
      <div className="om-diary-nav">
        <button type="button" aria-label={t('prevMonth')} onClick={() => shiftMonth(-1)}><CaretLeft size={15} weight="bold" /></button>
        <strong>{t('yearMonth', { y: cursor.y, m: cursor.m + 1 })}</strong>
        <button type="button" aria-label={t('nextMonth')} onClick={() => shiftMonth(1)}><CaretRight size={15} weight="bold" /></button>
      </div>
      <div className="om-diary-meta">
        <span>{t('monthCount', { n: monthCount })}</span>
        <button type="button" onClick={jumpToday}>{t('today')}</button>
      </div>
    </header>
    <div className="om-diary-week" aria-hidden="true">{WEEK_KEYS.map(key => <span key={key}>{t(key)}</span>)}</div>
    <div className="om-diary-grid" role="grid" aria-label={t('yearMonth', { y: cursor.y, m: cursor.m + 1 })}>
      {cells.map((cell, index) => {
        if (!cell) return <span className="om-diary-cell is-blank" key={`blank-${index}`} />;
        const entry = byDay.get(cell.day);
        const count = entry?.items.length || 0;
        const classes = ['om-diary-cell'];
        if (count) classes.push('has');
        if (cell.day === today) classes.push('is-today');
        if (cell.day === detail) classes.push('is-selected');
        return <button
          key={cell.day}
          type="button"
          role="gridcell"
          className={classes.join(' ')}
          disabled={!count}
          aria-pressed={cell.day === detail}
          aria-label={`${cell.day}${count ? t('nRecords', { n: count }) : t('noRecords')}`}
          onClick={() => count && setDetail(cell.day)}
        >
          <span className="om-diary-daynum">{cell.label}</span>
          {count > 0 && <span className="om-diary-badge">{count}</span>}
        </button>;
      })}
    </div>
    {detail && (
      <div className="om-diary-modal-backdrop" onClick={() => setDetail(null)}>
        <div className="om-diary-modal" role="dialog" aria-label={t('dayRecords', { day: detail })} onClick={(e) => e.stopPropagation()}>
          <header>
            <div>
              <strong>{detail}</strong>
              <small>{t('nTrails', { n: (byDay.get(detail)?.items || []).length })}</small>
            </div>
            <button type="button" className="icon-button" aria-label={t('close')} onClick={() => setDetail(null)}>
              <X size={18} />
            </button>
          </header>
          <div className="om-diary-items">
            {((byDay.get(detail)?.items) || []).map(item => (
              <button key={item.id} type="button" onClick={() => { setDetail(null); onOpenMemory?.(item.id); }}>
                <Article size={15} />
                <span>{item.title}</span>
                <CaretRight size={13} />
              </button>
            ))}
          </div>
        </div>
      </div>
    )}
  </section>;
}
