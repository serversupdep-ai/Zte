import { checkAll, type FullCheck } from "./check";
import { DEFAULT_TLDS } from "./domains";
import { summarize, type NameSummary } from "./score";
import { cleanName, pmap } from "./util";

export const MAX_BATCH = 25;

export interface BatchResult {
  checked: number;
  /** Best candidate first. */
  ranking: NameSummary[];
  /** Only present when details were requested. */
  details?: FullCheck[];
  trademarkReminder: string;
}

export async function checkMany(
  rawNames: string[],
  opts: { tlds?: string[]; country?: string; details?: boolean; github?: boolean } = {},
): Promise<BatchResult> {
  const names = [...new Set(rawNames.map(cleanName).filter(Boolean))].slice(0, MAX_BATCH);
  const full = await pmap(names, 3, (n) =>
    checkAll(n, opts.tlds?.length ? opts.tlds : DEFAULT_TLDS, opts.country ?? "de", { web: false, github: opts.github }),
  );
  const ranking = full.map(summarize).sort((a, b) => b.score - a.score);
  return {
    checked: names.length,
    ranking,
    ...(opts.details ? { details: full } : {}),
    trademarkReminder:
      "Scores cover domains and app stores only. Trademark registers (DPMA, EUIPO) must be reviewed separately: use trademark_links for the shortlist.",
  };
}
