import Checker from "@/components/Checker";
import McpSection from "@/components/McpSection";
import SkillSection from "@/components/SkillSection";

export default function Home() {
  return (
    <main className="page">
      <section className="hero">
        <span className="eyebrow">Domains · App Stores · Web · Trademark registers</span>
        <h1>
          Is your name <em>actually free?</em>
        </h1>
        <p className="lede">
          Check one name or a whole shortlist in seconds. Humans use the page, AI agents use the MCP endpoint.
        </p>
      </section>
      <Checker />
      <McpSection />
      <SkillSection />
    </main>
  );
}
