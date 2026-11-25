// The Python-served words (GET /api/words), shared by every screen.
import { createContext, useContext } from "react";
import type { Words } from "./api";

export const WordsContext = createContext<Words | null>(null);

export function useWords(): Words {
  const w = useContext(WordsContext);
  if (!w) throw new Error("words not loaded");
  return w;
}
