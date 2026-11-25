// The redesigned dashboard's root: one live feed for the whole page, then the chosen design.
import { useEffect } from "react";
import A from "./A";
import B from "./B";
import { UI } from "./bits";
import { LiveProvider, useLiveFeed, useRoute } from "./hooks";
import "./ui2.css";
import "./proof.css";

export default function App2() {
  const route = useRoute();
  const { live, failing } = useLiveFeed();
  useEffect(() => {
    document.documentElement.classList.add("ui2");
    return () => document.documentElement.classList.remove("ui2");
  }, []);
  if (!route) return null;
  // before the server's first answers: say so (it used to be a blank page, for as long as the server was away)
  if (!live) return <p className="ui2-boot" data-state={failing ? "failing" : "loading"} role="status">{failing ? UI.tips.bootFailing : UI.tips.bootLoading}</p>;
  // Labs live in design A's shell only (the design the demo uses)
  return <LiveProvider value={live}>{route.skin === "a" || route.screen === "labs" ? <A route={route} /> : <B route={route} />}</LiveProvider>;
}
