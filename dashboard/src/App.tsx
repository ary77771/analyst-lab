import { useEffect, useState } from "react";
import { Activity, BookOpen, BarChart3, Grid3x3, Copy } from "lucide-react";
import { api, type Mode, type Words } from "./api";
import { WordsContext } from "./words";
import { cx } from "./ui";
import { T } from "./ui-text";
import TwoMachines from "./screens/TwoMachines";
import Story from "./screens/Story";
import Scoreboard from "./screens/Scoreboard";
import Live from "./screens/Live";
import Coverage from "./screens/Coverage";
import Twin from "./screens/Twin";

type Tab = keyof typeof T.tabs;
const TABS: { id: Tab; icon: typeof Activity }[] = [
  { id: "live", icon: Activity },
  { id: "story", icon: BookOpen },
  { id: "twin", icon: Copy },
  { id: "coverage", icon: Grid3x3 },
  { id: "scoreboard", icon: BarChart3 },
];

function readTab(): Tab {
  const h = window.location.hash.replace("#", "").split("/")[0] as Tab;
  return h in T.tabs ? h : "live";
}
const readParam = () => decodeURIComponent(window.location.hash.replace("#", "").split("/")[1] ?? "") || null;

function Mark() {
  // the product mark: three strokes in the three inks (proven / suspected / can't be known)
  return (
    <svg width="22" height="22" viewBox="0 0 22 22" aria-hidden="true">
      <path d="M3 17 L9 5" stroke="var(--color-fact)" strokeWidth="2.6" strokeLinecap="round" />
      <path d="M10 17 L16 5" stroke="var(--color-hypo)" strokeWidth="2.6" strokeLinecap="round" strokeDasharray="3.2 3" />
      <path d="M17 17 L19.5 12" stroke="var(--color-gap)" strokeWidth="2.6" strokeLinecap="round" strokeDasharray="0.1 3.6" />
    </svg>
  );
}

export default function App() {
  const [words, setWords] = useState<Words | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>(readTab);
  const [param, setParam] = useState<string | null>(readParam);

  const [mode, setMode] = useState<Mode | null>(null);
  useEffect(() => {
    api.words().then(setWords).catch((e) => setErr(String(e)));
    api.mode().then(setMode).catch(() => setMode(null));
  }, []);
  useEffect(() => {
    const on = () => { setTab(readTab()); setParam(readParam()); window.scrollTo(0, 0); };
    window.addEventListener("hashchange", on);
    return () => window.removeEventListener("hashchange", on);
  }, []);

  if (err) return <p className="p-8 text-alert">{T.errorPrefix} {err}</p>;
  if (!words) return <p className="p-8 text-fg-muted">{T.loading}</p>;

  return (
    <WordsContext.Provider value={words}>
      <div className="flex min-h-full flex-col">
        <header className="sticky top-0 z-10 border-b border-border bg-canvas">
          <div className="mx-auto flex h-14 max-w-[1680px] items-center gap-8 px-6">
            <div className="flex items-center gap-2.5">
              <Mark />
              <span className="text-[15px] font-semibold">{T.appName}</span>
            </div>
            <nav className="flex h-full items-stretch gap-1">
              {TABS.map(({ id, icon: Icon }) => (
                <a key={id} href={`#${id}`}
                  className={cx("relative inline-flex items-center gap-2 px-3 text-[14px] font-semibold transition-colors duration-150",
                    tab === id ? "text-fg" : "text-fg-muted hover:text-fg")}>
                  <Icon size={15} />{T.tabs[id]}
                  {tab === id && <span className="absolute inset-x-2 bottom-0 h-[2px] rounded-full bg-accent" />}
                </a>
              ))}
            </nav>
            {mode?.badge && (
              <span className={cx("ml-auto inline-flex items-center gap-2 rounded-[6px] px-3 py-1.5 text-[14px] font-semibold",
                mode.mode === "live" ? "bg-accent/15 text-accent ring-1 ring-accent/50" : "bg-fg text-canvas")}>
                {mode.mode === "live" && <span className="h-2 w-2 animate-pulse rounded-full bg-accent" />}
                {mode.badge}{mode.detail ? <span className="font-normal opacity-80">· {mode.detail}</span> : null}
              </span>
            )}
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1680px] flex-1 px-6 py-6">
          {tab === "twoMachines" ? <TwoMachines /> : tab === "story" ? <Story alertId={param} /> : tab === "scoreboard" ? <Scoreboard /> :
            tab === "coverage" ? <Coverage /> : tab === "twin" ? <Twin /> : <Live />}
        </main>
      </div>
    </WordsContext.Provider>
  );
}
