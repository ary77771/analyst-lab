// Plain words for the technical names on the night-tools pages (W3-6). The words come from Python (WORDS.jargon);
// each term is shown with a dotted underline and its plain line on hover, and the lines are also written out
// (a hover alone is not enough on a projector or a touch screen).
export function Jargon({ terms }: { terms?: Record<string, string> | null }) {
  const entries = Object.entries(terms ?? {});
  if (!entries.length) return null;
  return (
    <p className="ft-jargon">
      <span className="ft-muted">In plain words: </span>
      {entries.map(([term, plain], i) => (
        <span key={term}>
          <abbr title={plain}>{term}</abbr> = {plain}{i < entries.length - 1 ? "; " : "."}
        </span>
      ))}
    </p>
  );
}
