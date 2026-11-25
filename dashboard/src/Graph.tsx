// A thin React wrapper around the vendored Cytoscape.js (loaded by index.html, not bundled).
// Positions come from the caller (preset layout), so the picture is laid out by time and machine.
// The viewer can't zoom or pan by accident (a mouse wheel scrolls the page); "Fit" re-centres it.
import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Cy = any;
declare global {
  interface Window { cytoscape: (opts: unknown) => Cy }
}

export interface GraphProps {
  elements: unknown[];
  style: unknown[];
  /** id of the selected edge: everything not touching it is dimmed */
  selected?: string | null;
  onSelect?: (id: string | null) => void;
  /** ids of edges to hide (story playback); a node is hidden while all its edges are */
  hidden?: Set<string> | null;
  className?: string;
}

export interface GraphHandle { fit: () => void }

const css = (name: string) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
export const colors = () => ({
  fact: css("--color-fact"), hypothesis: css("--color-hypo"), gap: css("--color-gap"), text: css("--color-fg"),
  muted: css("--color-fg-muted"), subtle: css("--color-fg-subtle"), surface: css("--color-surface"),
  raised: css("--color-raised"), border: css("--color-border"), strong: css("--color-border-strong"),
  accent: css("--color-accent"), canvas: css("--color-canvas"),
});

/** Shared rules every graph uses on top of its own style: dimming, hiding, transitions. */
export const baseStyle = () => [
  { selector: "node, edge", style: { "transition-property": "opacity", "transition-duration": 320 } },
  { selector: ".dim", style: { opacity: 0.18 } },
  { selector: ".hid", style: { opacity: 0, events: "no" } },
];

const Graph = forwardRef<GraphHandle, GraphProps>(function Graph({ elements, style, selected, onSelect, hidden, className }, ref) {
  const box = useRef<HTMLDivElement>(null);
  const cy = useRef<Cy>(null);
  const fit = () => { const g = cy.current; if (g) { g.resize(); g.fit(g.elements(":visible"), 36); } };
  useImperativeHandle(ref, () => ({ fit }));

  useEffect(() => {
    if (!box.current || !window.cytoscape) return;
    const g = window.cytoscape({
      container: box.current, elements, style: [...style, ...baseStyle()], layout: { name: "preset", fit: true, padding: 36 },
      userZoomingEnabled: false, userPanningEnabled: false, boxSelectionEnabled: false, autoungrabify: true,
    });
    g.on("tap", "edge", (ev: Cy) => onSelect?.(ev.target.id()));
    g.on("tap", (ev: Cy) => { if (ev.target === g) onSelect?.(null); });
    cy.current = g;
    const ro = new ResizeObserver(() => fit());
    ro.observe(box.current);
    return () => { ro.disconnect(); g.destroy(); cy.current = null; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [elements, style]);

  useEffect(() => {
    const g = cy.current;
    if (!g) return;
    g.elements().removeClass("sel dim");
    if (!selected) return;
    const e = g.getElementById(selected);
    if (!e || e.empty()) return;
    const keep = e.union(e.connectedNodes()).union(e.connectedNodes().parents());
    g.elements().not(keep).not(".lane").addClass("dim");
    e.addClass("sel");
  }, [selected, elements]);

  useEffect(() => {
    const g = cy.current;
    if (!g) return;
    g.elements().removeClass("hid");
    if (!hidden || hidden.size === 0) return;
    g.edges().forEach((e: Cy) => { if (hidden.has(e.id())) e.addClass("hid"); });
    g.nodes().not(":parent").not(".lane").forEach((n: Cy) => {
      const edges = n.connectedEdges();
      if (edges.length && edges.every((e: Cy) => hidden.has(e.id()))) n.addClass("hid");
    });
  }, [hidden, elements]);

  return <div ref={box} className={className} />;
});

export default Graph;
