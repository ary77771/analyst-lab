// The night-tools labs, about one alert (wave 3): the line that says which alert a page is showing, with a way
// back to everything. The alert itself lives in the address (useAlertParam from ../kit).
export function AlertScope({ alert, title, onClear, what }: { alert: string | null; title?: string | null; onClear: () => void; what: string }) {
  if (!alert) return null;
  return (
    <p className="ft-scope">
      <span className="ft-muted">{what} for the alert </span><b>{title ?? alert}</b>
      <button type="button" className="ft-a ft-linkbtn" onClick={onClear}>show everything instead</button>
    </p>
  );
}
