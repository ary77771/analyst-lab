// Icons. Python chooses every icon NAME (engine/report.py ICON_NAMES: an icon is a claim too, so a
// folder never gets a file picture unless the record proves a file); this file only maps names to
// pictures. Graph nodes need image URLs, so their icons are inline SVG built from Lucide's path data
// (https://lucide.dev, ISC licence, the same set as the lucide-react package used in lists).
import { AppWindow, ArrowDownLeft, ArrowUpRight, AtSign, Box, CircleHelp, Copy, EyeOff, FileCode, FilePlus, FileX,
  Globe, Plug, PackagePlus, Play, Repeat, Stamp, type LucideIcon } from "lucide-react";

const PATHS: Record<string, string> = {
  program: '<rect x="2" y="4" width="20" height="16" rx="2"/><path d="M10 4v4"/><path d="M2 8h20"/><path d="M6 4v4"/>',
  file: '<path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z"/><path d="M14 2v4a2 2 0 0 0 2 2h4"/>',
  item: '<path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z"/><path d="m3.3 7 8.7 5 8.7-5"/><path d="M12 22V12"/>',
  address: '<circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/>',
  name: '<circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-4 8"/>',
  port: '<path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/>',
  autostart: '<path d="m17 2 4 4-4 4"/><path d="M3 11v-1a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v1a4 4 0 0 1-4 4H3"/>',
};
const KIND_TO_NODE_ICON: Record<string, string> = { process: "program", file: "item", endpoint: "address", dns: "name", port: "port", autostart: "autostart" };

/** A node picture for Cytoscape. `name` is Python's icon name; `kind` is the fallback (old data). */
export function iconUrl(name: string | undefined, color: string, kind?: string): string {
  const p = PATHS[name ?? ""] ?? PATHS[KIND_TO_NODE_ICON[kind ?? ""] ?? "item"];
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${p}</svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

/** Step icons for lists (Python's EDGE_ICONS names). No download or danger pictures exist here. */
export const STEP_ICON: Record<string, LucideIcon> = {
  "program-start": Play, "connection-out": ArrowUpRight, "connection-in": ArrowDownLeft, "item-created": PackagePlus,
  "file-created": FilePlus, "item-deleted": FileX, "name-lookup": AtSign, "program-file": FileCode, "port-open": Plug,
  "port-closed": Plug, autostart: Repeat, mark: Stamp, "same-content": Copy, suspected: CircleHelp, unknown: EyeOff,
  program: AppWindow, address: Globe, item: Box, other: Box,
};
