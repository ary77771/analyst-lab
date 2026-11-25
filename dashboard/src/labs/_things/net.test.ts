import { describe, expect, it } from "vitest";
import { NO_ANSWER } from "../kit";
import { getJsonPatient, plainError } from "./net";

const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

describe("asking a restarting server", () => {
  it("never shows the browser's own words", () => {
    expect(plainError(new TypeError("Failed to fetch"))).toBe(NO_ANSWER);
    expect(plainError(new Error("no such case"))).toBe("no such case");
  });

  it("asks again while the server does not answer, then gets the answer", async () => {
    let calls = 0;
    const f = (async () => { calls += 1; if (calls < 3) throw new TypeError("Failed to fetch"); return ok([1, 2]); }) as typeof fetch;
    await expect(getJsonPatient<number[]>("/x", 5, 1, f)).resolves.toEqual([1, 2]);
    expect(calls).toBe(3);
  });

  it("gives up in plain words, and passes an error answer on at once", async () => {
    const down = (async () => { throw new TypeError("Failed to fetch"); }) as typeof fetch;
    await expect(getJsonPatient("/x", 3, 1, down)).rejects.toThrow(NO_ANSWER);
    let calls = 0;
    const missing = (async () => { calls += 1; return new Response(JSON.stringify({ detail: "no such case" }), { status: 404 }); }) as typeof fetch;
    await expect(getJsonPatient("/x", 5, 1, missing)).rejects.toThrow("no such case");
    expect(calls).toBe(1);
  });
});
