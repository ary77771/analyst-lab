// A test fixture (not part of the build): a lab that is in order.
import { Gauge } from "lucide-react";
import type { Lab } from "../../registry";

export const lab: Lab = { id: "fine", title: "A lab that is in order", blurb: "Stands in for any working lab.", icon: Gauge, Component: () => null };
