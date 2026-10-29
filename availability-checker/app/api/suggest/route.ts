import { NextRequest, NextResponse } from "next/server";
import { suggestDomains } from "@/lib/suggest";
import { cleanName } from "@/lib/util";

export const maxDuration = 30;

export async function GET(req: NextRequest) {
  const name = cleanName(req.nextUrl.searchParams.get("name") ?? "");
  if (!name) return NextResponse.json({ error: "name is required" }, { status: 400 });
  return NextResponse.json({ name, suggestions: await suggestDomains(name) });
}
