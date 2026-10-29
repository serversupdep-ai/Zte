import { NextRequest, NextResponse } from "next/server";
import { checkAll } from "@/lib/check";
import { DEFAULT_TLDS } from "@/lib/domains";
import { cleanName } from "@/lib/util";

export const maxDuration = 30;

export async function GET(req: NextRequest) {
  const p = req.nextUrl.searchParams;
  const name = cleanName(p.get("name") ?? "");
  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });
  const tlds = (p.get("tlds") ?? "")
    .split(",")
    .map((t) => t.trim().toLowerCase().replace(/^\./, ""))
    .filter((t) => /^[a-z]{2,24}$/.test(t))
    .slice(0, 20);
  return NextResponse.json(await checkAll(name, tlds.length ? tlds : DEFAULT_TLDS, p.get("country") ?? "de"));
}
