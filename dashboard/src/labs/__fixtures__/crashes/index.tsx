// A test fixture (not part of the build): a lab that loads, and whose page throws when it is drawn.
import { Gauge } from "lucide-react";
import type { Lab } from "../../registry";

function Crashes(): never {
  throw new Error("this lab's page crashes on purpose");
}

export const lab: Lab = { id: "crashes", title: "A lab whose page crashes", blurb: "Stands in for a lab with a mistake in its page.", icon: Gauge, Component: Crashes };
