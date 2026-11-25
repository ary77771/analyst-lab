// "Evil twin": two look-alike blind stories side by side (engine/dashboard/twin.py).
import { useEffect, useState } from "react";
import { BellOff, Siren } from "lucide-react";
import { api, type Twin as TW } from "../api";
import { Card, Eyebrow, LevelTag, cx } from "../ui";
import { T } from "../ui-text";

function Side({ s, w, floor }: { s: TW["sides"][number]; w: TW["words"]; floor: string }) {
  const attack = s.kind !== "innocent";
  return (
    <Card className={cx("flex flex-col", s.raised.length ? "border-t-2 !border-t-alert" : "border-t-2 !border-t-border-strong")}>
      <Eyebrow>{s.scenario} · {w.kind[s.kind]}</Eyebrow>
      <h2 className="mt-1.5 text-[22px] font-semibold leading-snug"><span className="mr-2 text-[15px] font-normal text-fg-muted">{w.writer_title}</span>{s.title}</h2>

      <div className={cx("mt-5 flex items-center gap-4 rounded-[10px] border px-5 py-4",
        s.raised.length ? "border-alert/60 bg-alert/10" : "border-border bg-raised")}>
        {s.raised.length ? <Siren size={30} className="text-alert" /> : <BellOff size={30} className="text-fg-muted" />}
        <div className="min-w-0">
          <div className={cx("text-[20px] font-semibold", s.raised.length ? "text-alert" : "text-fg")}>
            {s.raised.length ? `${w.raised}: ${s.raised.length}` : w.none_raised}</div>
          {s.raised.map((a) => (
            <div key={a.title} className="mt-2 flex items-start gap-2 text-[15px]"><LevelTag level={a.level} />
              <span>{a.plain ?? a.title}{a.plain && <span className="block text-[13px] text-fg-subtle">{a.title}</span>}</span></div>
          ))}
        </div>
      </div>

      {s.below_floor.length > 0 && (
        <div className="mt-4">
          <Eyebrow className="mb-1.5">{w.below.replace("{floor}", floor)}</Eyebrow>
          {s.below_floor.map((a) => <div key={a.title} className="mt-1 flex items-center gap-2 text-[15px] text-fg-muted"><LevelTag level={a.level} />{a.plain ?? a.title}</div>)}
        </div>
      )}

      {attack && s.raised.some((a) => a.steps?.length) && (
        <div className="mt-4">
          <Eyebrow className="mb-1.5">{w.steps}</Eyebrow>
          <ol className="space-y-1 text-[14px] text-fg">
            {(s.raised.find((a) => (a.steps?.length ?? 0) > 1)?.steps ?? []).map((st, i) => (
              <li key={i} className="flex gap-2"><span className="num w-5 flex-none text-fg-subtle">{i + 1}</span>{st}</li>
            ))}
          </ol>
        </div>
      )}

      {s.verdicts && (
        <div className="mt-auto pt-5">
          <Eyebrow className="mb-1.5">{w.verdicts}</Eyebrow>
          <div className="num flex gap-6 text-[15px]">
            <span className="text-fg-muted">v3: <span className="text-fg">{s.verdicts.v3}</span></span>
            <span className="text-fg-muted">v4: <span className="font-semibold text-fg">{s.verdicts.v4}</span></span>
          </div>
        </div>
      )}
    </Card>
  );
}

export default function Twin() {
  const [d, setD] = useState<TW | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => { api.twin().then(setD).catch((e) => setErr(String(e))); }, []);
  if (err) return <p className="text-alert">{T.errorPrefix} {err}</p>;
  if (!d) return <p className="text-fg-muted">{T.loading}</p>;
  const w = d.words;
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-[32px] font-semibold">{w.title}</h1>
        <p className="mt-2 max-w-[80ch] text-[16px] leading-relaxed text-fg-muted">{w.intro}</p>
        <p className="mt-1 max-w-[80ch] text-[14px] text-fg-subtle"><a href="#scoreboard" className="underline decoration-border-strong underline-offset-4 hover:text-fg">{w.picked}</a></p>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">{d.sides.map((s) => <Side key={s.scenario} s={s} w={w} floor={d.floor} />)}</div>
      <Card><p className="max-w-[90ch] text-[16px] leading-relaxed">{w.difference}</p></Card>
      <p className="text-[12px] text-fg-subtle">{d.source}</p>
    </div>
  );
}
