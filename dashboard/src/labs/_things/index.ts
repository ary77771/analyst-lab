// Shared pieces for every lab (night-pivot, W3-4): import { Thing, PlusCase } from "../_things";
// (index.ts, not index.tsx: the Labs registry only picks up ./<id>/index.tsx, so this folder is never a lab.)
export { Thing, type ThingProps } from "./Thing";
export { PlusCase } from "./PlusCase";
export { FIELD_TO_KIND, THING_KINDS, plusCasePin, thingHref, thingKind, thingShort, thingValue, type ThingKind } from "./things";
