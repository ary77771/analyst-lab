import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "./index.css";
import App from "./App";
import App2 from "./ui2/App2";
import { parseRoute } from "./ui2/logic";

// #a/... and #b/... open the two redesigned dashboards (until Yousif picks one); everything else is
// today's app. Moving between the old and the new reloads the page, so their styles never mix.
const isNew = () => parseRoute(window.location.hash) !== null;
const startedNew = isNew();
window.addEventListener("hashchange", () => { if (isNew() !== startedNew) window.location.reload(); });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    {startedNew ? <App2 /> : <App />}
  </StrictMode>,
);
