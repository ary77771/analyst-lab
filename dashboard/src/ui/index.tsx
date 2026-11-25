// The component kit (dashboard/DESIGN-SYSTEM.md). Screens compose these; they don't invent styles.
import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { Ink } from "../api";
import { useWords } from "../words";

const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

export const INK_TEXT: Record<Ink, string> = { fact: "text-fact", hypothesis: "text-hypo", gap: "text-gap" };
export const INK_BORDER: Record<Ink, string> = { fact: "border-fact", hypothesis: "border-hypo", gap: "border-gap" };
export const INK_LINE: Record<Ink, "solid" | "dashed" | "dotted"> = { fact: "solid", hypothesis: "dashed", gap: "dotted" };

export function Eyebrow({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cx("text-[12px] font-semibold uppercase tracking-[0.06em] text-fg-subtle", className)}>{children}</div>;
}

export function Card({ title, eyebrow, actions, children, className, pad = true }: {
  title?: ReactNode; eyebrow?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; pad?: boolean;
}) {
  return (
    <section className={cx("rounded-[10px] border border-border bg-surface", className)}>
      {(title || eyebrow || actions) && (
        <header className="flex items-start justify-between gap-4 px-5 pt-4 pb-3 border-b border-border">
          <div className="min-w-0">
            {eyebrow && <Eyebrow className="mb-1">{eyebrow}</Eyebrow>}
            {title && <h2 className="text-[16px] font-semibold text-fg">{title}</h2>}
          </div>
          {actions && <div className="flex flex-none items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={pad ? "p-5" : undefined}>{children}</div>
    </section>
  );
}

export function LineSample({ ink, className }: { ink: Ink; className?: string }) {
  return <span className={cx("ink-line", INK_LINE[ink], INK_BORDER[ink], className)} />;
}

/** The only way an ink appears in text: line sample + word (+ the band's plain word). */
export function InkTag({ ink, band, size = "md" }: { ink: Ink; band?: string | null; size?: "sm" | "md" }) {
  const w = useWords();
  const bandWord = band ? (w.bands[band] ?? (band.includes("not assessable") ? w.band_not_assessable : band)) : null;
  return (
    <span className={cx("inline-flex items-center gap-2 whitespace-nowrap font-semibold", INK_TEXT[ink], size === "sm" ? "text-[12px]" : "text-[13px]")}>
      <LineSample ink={ink} className="!w-4" />
      {w.inks[ink].word}
      {bandWord && <span className="font-normal text-fg-muted">· {bandWord}</span>}
    </span>
  );
}

const LEVEL_STYLE: Record<string, string> = {
  informational: "border border-alert/40 text-alert/80",
  low: "border border-alert/60 text-alert",
  medium: "bg-alert/15 border border-alert/50 text-alert",
  high: "bg-alert text-canvas border border-alert",
  critical: "bg-alert text-canvas border border-alert ring-2 ring-alert/40",
};

export function LevelTag({ level, label }: { level: string; label?: string }) {
  return (
    <span className={cx("inline-flex items-center rounded-[6px] px-2.5 py-1 text-[14px] font-semibold uppercase tracking-[0.04em]", LEVEL_STYLE[level] ?? LEVEL_STYLE.medium)}>
      {label ? `${label} ${level}` : level}
    </span>
  );
}

export function Button({ variant = "ghost", icon, children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "ghost"; icon?: ReactNode;
}) {
  return (
    <button {...rest}
      className={cx("inline-flex items-center gap-2 rounded-[6px] px-3 py-1.5 text-[13px] font-semibold transition-colors duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50",
        variant === "primary" ? "bg-accent text-accent-fg hover:bg-accent/90" : "text-fg-muted hover:bg-raised hover:text-fg",
        className)}>
      {icon}{children}
    </button>
  );
}

export function Stat({ value, label, ink }: { value: ReactNode; label: ReactNode; ink?: Ink }) {
  return (
    <div className="min-w-0">
      <div className={cx("num text-[48px] font-semibold leading-none tracking-[-0.02em]", ink ? INK_TEXT[ink] : "text-fg")}>{value}</div>
      <div className="mt-2 text-[14px] leading-snug text-fg-muted">{label}</div>
    </div>
  );
}

export function KeyValue({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-[13px]">
      {rows.map(([k, v], i) => (
        <div key={i} className="contents">
          <dt className="text-fg-muted">{k}</dt>
          <dd className="min-w-0 break-words text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Legend() {
  const w = useWords();
  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 text-[13px] text-fg-muted">
      {w.legend.map((l) => (
        <span key={l.ink} className="inline-flex items-center gap-2">
          <LineSample ink={l.ink} />{l.text}
        </span>
      ))}
    </div>
  );
}

export { cx };
