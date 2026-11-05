import { useEffect, useId, useRef } from 'react';
import { createPortal } from 'react-dom';
import { AlertCircle, LoaderCircle, X, type LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';

export function Modal({ title, description, children, onClose, busy = false, wide = false }: {
  title: string; description?: string; children: ReactNode; onClose: () => void; busy?: boolean; wide?: boolean;
}) {
  const id = useId();
  const dialog = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    dialog.current?.querySelector<HTMLElement>('[data-autofocus], input, button')?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) close.current();
      if (event.key !== 'Tab') return;
      const elements = [...(dialog.current?.querySelectorAll<HTMLElement>('button:not(:disabled), a[href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex="0"]') ?? [])].filter(element => element.getClientRects().length > 0);
      const first = elements[0];
      const last = elements.at(-1);
      if (!first) { event.preventDefault(); return; }
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', keydown);
    return () => { document.removeEventListener('keydown', keydown); document.body.style.overflow = previousOverflow; previous?.focus(); };
  }, [busy]);
  return createPortal(<div className="modal-backdrop" onMouseDown={event => { if (event.target === event.currentTarget && !busy) onClose(); }}>
    <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby={id} aria-describedby={description ? `${id}-description` : undefined} className={`modal ${wide ? 'modal-wide' : ''}`}>
      <div className="modal-heading"><div><h2 id={id}>{title}</h2>{description && <p id={`${id}-description`}>{description}</p>}</div>
        <button className="icon-button" aria-label="Close dialog" onClick={onClose} disabled={busy}><X size={19} /></button>
      </div>{children}
    </div>
  </div>, document.body);
}

export function ErrorBanner({ message, onDismiss, onRetry }: { message: string; onDismiss?: () => void; onRetry?: () => void }) {
  return <div className="error-banner" role="alert"><AlertCircle size={18} /><span>{message}</span>
    {onRetry && <button className="text-button" onClick={onRetry}>Try again</button>}
    {onDismiss && <button className="icon-button" aria-label="Dismiss error" onClick={onDismiss}><X size={16} /></button>}
  </div>;
}

export function EmptyState({ icon: Icon, title, children, action }: { icon: LucideIcon; title: string; children: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><span className="empty-icon"><Icon size={25} strokeWidth={1.6} /></span><h3>{title}</h3><p>{children}</p>{action}</div>;
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return <div className="loading-state" role="status"><LoaderCircle size={19} className="spin" /><span>{label}</span></div>;
}

export function Badge({ children, tone = 'neutral', dot = false }: { children: ReactNode; tone?: 'neutral' | 'green' | 'amber' | 'red' | 'blue'; dot?: boolean }) {
  return <span className={`badge badge-${tone}`}>{dot && <span className="badge-dot" />}{children}</span>;
}

export function formatDate(value: string | null | undefined, includeTime = false) {
  if (!value) return 'Not reported';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return 'Not reported';
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric', ...(includeTime ? { hour: '2-digit', minute: '2-digit' } : {}) }).format(date);
}

export function money(value: number | undefined) {
  return value === undefined || !Number.isFinite(value) ? 'Not reported' : new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 2 }).format(value);
}

export function humanize(value: string) { return value.replaceAll('_', ' ').replace(/^./, character => character.toUpperCase()); }

export function stageTone(stage: string): 'neutral' | 'green' | 'amber' | 'red' | 'blue' {
  if (['completed', 'published', 'passed', 'approved'].includes(stage)) return 'green';
  if (['failed', 'blocked', 'rejected', 'CRITICAL', 'HIGH'].includes(stage)) return 'red';
  if (['needs_attention', 'awaiting_approval', 'clarification', 'unavailable', 'needs_credentials', 'MEDIUM'].includes(stage)) return 'amber';
  if (['building', 'implementation', 'deployment', 'verification', 'queued', 'preview', 'ready'].includes(stage)) return 'blue';
  return 'neutral';
}
