/** Lowercase, strip diacritics, keep only a-z0-9 and hyphens. Used for domain labels. */
export function toLabel(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/ß/g, "ss")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[\s_]+/g, "")
    .replace(/[^a-z0-9-]/g, "")
    .replace(/^-+|-+$/g, "");
}

/** Normalised form for comparing brand names (letters and digits only). */
export function norm(input: string): string {
  return input
    .toLowerCase()
    .replace(/ß/g, "ss")
    .normalize("NFKD")
    .replace(/[̀-ͯ]/g, "")
    .replace(/[^a-z0-9]/g, "");
}

export function cleanName(input: string): string {
  return input.trim().replace(/\s+/g, " ").slice(0, 40);
}

/** Run `fn` over `items` with at most `limit` in flight. Order is preserved. */
export async function pmap<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export const UA = "Mozilla/5.0 (compatible; namevet/0.1)";
