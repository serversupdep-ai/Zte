"use client";

import { useRef, useState } from "react";
import NameCard from "@/components/NameCard";
import Summary from "@/components/Summary";
import { Search } from "@/components/icons";
import type { FullCheck } from "@/lib/check";

type Entry = { data?: FullCheck; error?: string };
const EXAMPLES = ["Assay, Plumb, Tidepool", "Fieldnote"];

export default function Checker() {
  const [input, setInput] = useState("");
  const [names, setNames] = useState<string[]>([]);
  const [results, setResults] = useState<Record<string, Entry>>({});
  const [busy, setBusy] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);

  async function run(value = input) {
    const list = [...new Set(value.split(/[,\n]/).map((s) => s.trim()).filter(Boolean))].slice(0, 8);
    if (!list.length) return;
    setNames(list);
    setResults({});
    setBusy(true);
    await Promise.all(
      list.map(async (n) => {
        try {
          const r = await fetch(`/api/check?name=${encodeURIComponent(n)}`);
          if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error ?? `HTTP ${r.status}`);
          const data: FullCheck = await r.json();
          setResults((p) => ({ ...p, [n]: { data } }));
        } catch (err: any) {
          setResults((p) => ({ ...p, [n]: { error: err.message } }));
        }
      }),
    );
    setBusy(false);
  }

  function grow(el: HTMLTextAreaElement) {
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 160) + "px";
  }

  const done = names.map((n) => results[n]?.data).filter(Boolean) as FullCheck[];

  return (
    <>
      <form
        className="search"
        onSubmit={(e) => {
          e.preventDefault();
          run();
        }}
      >
        <Search />
        <textarea
          ref={area}
          value={input}
          rows={1}
          aria-label="Names to check"
          placeholder="Type a name, or paste a list separated by commas or new lines"
          onChange={(e) => {
            setInput(e.target.value);
            grow(e.target);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              run();
            }
          }}
        />
        <button className="btn-primary" disabled={busy || !input.trim()}>
          {busy ? <span className="spin" aria-hidden /> : null}
          {busy ? "Checking" : "Check"}
        </button>
      </form>
      {!names.length && (
        <p className="examples">
          Try
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              type="button"
              className="pill"
              onClick={() => {
                setInput(ex);
                run(ex);
              }}
            >
              {ex}
            </button>
          ))}
        </p>
      )}

      {done.length > 1 && <Summary items={done} total={names.length} />}
      <div className="results">
        {names.map((n) => (
          <NameCard key={n} name={n} {...results[n]} />
        ))}
      </div>
    </>
  );
}
