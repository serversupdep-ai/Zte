import { readFile } from "node:fs/promises";
import path from "node:path";

// Read at build time, so the file ships as a static response.
export const dynamic = "force-static";

export async function GET() {
  const file = path.join(process.cwd(), "skills", "creative-naming", "SKILL.md");
  return new Response(await readFile(file, "utf8"), {
    headers: {
      "content-type": "text/markdown; charset=utf-8",
      "content-disposition": 'inline; filename="SKILL.md"',
      "access-control-allow-origin": "*",
    },
  });
}
