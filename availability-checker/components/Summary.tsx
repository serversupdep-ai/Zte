"use client";

import type { FullCheck } from "@/lib/check";
import { summarize } from "@/lib/score";

const V: Record<string, string> = { none: "clear", similar: "similar", exact: "taken", error: "failed" };
const kindOf = (v: string) => (v === "none" ? "ok" : v === "similar" ? "warn" : "bad");

export default function Summary({ items, total }: { items: FullCheck[]; total: number }) {
  const rows = items.map(summarize).sort((a, b) => b.score - a.score);
  const has = (r: (typeof rows)[number], tld: string) => r.domainsFree.some((d) => d.endsWith(`.${tld}`));

  return (
    <section className="panel summary" aria-label="Comparison">
      <div className="panel-head">
        <h2>Ranking</h2>
        <span className="muted">
          {items.length}/{total} checked · domains and stores only
        </span>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Score</th>
              <th>.com</th>
              <th>.de</th>
              <th>iOS</th>
              <th>Android</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={r.name}>
                <td className="strong">
                  {i === 0 && rows.length > 1 && <span className="best">Best</span>}
                  {r.name}
                </td>
                <td>
                  <span className="meter" role="img" aria-label={`Score ${r.score} of 100`}>
                    <span className={`fill ${r.verdict}`} style={{ width: `${r.score}%` }} />
                  </span>
                  <span className="num">{r.score}</span>
                </td>
                <td><span className={`tag ${has(r, "com") ? "ok" : "bad"}`}>{has(r, "com") ? "free" : "taken"}</span></td>
                <td><span className={`tag ${has(r, "de") ? "ok" : "bad"}`}>{has(r, "de") ? "free" : "taken"}</span></td>
                <td><span className={`tag ${kindOf(r.ios)}`}>{V[r.ios]}</span></td>
                <td><span className={`tag ${kindOf(r.android)}`}>{V[r.android]}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
