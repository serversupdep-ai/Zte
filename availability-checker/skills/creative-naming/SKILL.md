---
name: creative-naming
description: Invent genuinely creative, memorable names for a product, app, startup, library or brand, and vet them for real availability with the namevet MCP tools. Use whenever the user asks for name ideas, a rebrand, a project or repo name, a domain-worthy name, or "something better than generic AI names". Replaces default LLM naming (Lumora, Nexora, -ly, -ify, Nova) with distinct names that have a story, then checks domains, app stores, GitHub and trademark registers before recommending anything.
---

# Creative naming

Default LLM naming is slop: the same smooth Latin-ish syllables, the same suffixes, the same "inspiring" words. This skill replaces that with a real naming process and an availability check. A name is only recommended after it has been vetted.

## 1. Brief (ask at most 3 questions, otherwise assume and say so)

- What does it do, and for whom (one sentence)?
- Tone: playful, serious, technical, warm, premium, rebellious?
- Constraints: markets and languages (DE, EN, ...), must-have TLD (.com, .de, .dev), app store, GitHub, trademark classes (software is usually 9, 35, 42).

## 2. Banned: the slop list

Do not propose, and cut if you catch yourself generating:

- **Pseudo-Latin syllable mashups** ending in -a, -o, -ia, -ora, -ova, -ara, -ix, -ex: Lumora, Nuvia, Kelvio, Zenvio, Veridia, Nexora, Avalon-style fillers.
- **Startup suffixes and prefixes**: -ly, -ify, -io, -ai, -hub, -labs, -ware, -tech, -hq, -kit, get-, try-, use-, my-, the-. Never "rescue" a taken name by bolting one on.
- **Stock inspirational words**: Nova, Lumen, Luma, Zenith, Apex, Nexus, Vertex, Quantum, Fusion, Synergy, Pulse, Flux, Aura, Orbit, Echo, Atlas, Sage, Prism, Spark, Bloom, Forge, Beacon, Catalyst, Elevate, Vivid.
- **Adjective + noun compounds with no tension**: Brightloop, Clearpath, Smartflow, Swiftbase.
- **Vowel-dropping** (Flickr, Tumblr, Handlr style) and random doubled or swapped letters.
- **Anything that sounds like it came from a generator** and could belong to a bank, a vitamin or a SaaS equally.

## 3. Strategies (generate across at least five)

1. **Foreign craft word.** A precise term from a trade or field unrelated to software: typography, sailing, forestry, assaying, cartography, glassblowing, beekeeping, cheesemaking. Example direction for a name-vetting tool: words for *testing quality* such as plumb (plumb line), assay (testing metal), touchstone.
2. **Concrete object or place.** A physical thing with the right behavior, not a feeling. Tidepool, ledger, gantry, windlass, kiln.
3. **Verb as name.** An action the user does. Short, strong, easy to say in a sentence.
4. **Borrowed language.** German, Dutch, Finnish, Japanese, Old English. It must be pronounceable and neutral in every target market.
5. **Tension pair.** Two real words that should not go together but make a picture. Only if the join is surprising, not generic.
6. **Compressed phrase.** A short phrase from the product's story, reduced to one or two words.
7. **Sound first.** Choose the consonant texture for the brand (plosives punchy, sibilants smooth), two syllables, stress on the first, then find a word that fits.
8. **Honest anti-name.** Understated or deliberately plain: a name that is confident enough not to try.

## 4. Process

1. Generate **5 directions x 6-8 names** (about 40). Mix strategies. Write each name with a 3-word rationale.
2. **Slop filter.** Remove anything on the banned list. Say how many you cut.
3. **Say-it test.** Cut names that fail any of:
   - Can someone spell it after hearing it once?
   - Is it 1-3 syllables?
   - Is it pronounceable in German and English?
   - Does it have no bad meaning in the target languages (check homophones)?
   - Does it still work as a verb or in a sentence ("ship it with ...")?
4. **Vet the survivors** (up to 25) in one call with the namevet MCP tool `check_names`. Add `github: true` for developer tools or open source. Read the notes, not only the score.
5. Drop names that are taken in the way that matters to this brief (usually: .com or primary TLD, same-category app listing, popular GitHub repo). A taken .com alone is not fatal if the brief accepts .de, .dev or .app.
6. If almost everything is taken, **change direction**. Do not add suffixes.
7. **Shortlist 3-5.** For the top 2-3 call `trademark_links` and give the Nice classes.

If the namevet MCP tools are not connected, say so, still do steps 1-3, and ask the user to run the survivors through the namevet web page or connect the MCP server. Never claim a name is available without a tool result.

## 5. Output

For the shortlist, one block per name:

```
Name: Assay
Strategy: foreign craft word (testing metal for purity)
Why: it is literally what the tool does, one hard-edged syllable pair
Vetted: .de free, .dev free, .com taken | App Store clear | GitHub handle free
Risks: rare word, mispronounced "ass-ay"
Taglines: "Assay your name." / "Test before you stamp it."
```

Then:
- A short list of the strongest rejected names and why (so the user can overrule you).
- The trademark links and this reminder: scores cover domains, stores and GitHub only; trademark registers and a professional check are still needed before launch.

## Rules

- Quality over count. Five distinct names beat twenty variations.
- Never propose a name before vetting it. Never present unvetted names as "available".
- Never reuse a name from the banned list because it vetted well.
- Be honest about weak shortlists. "Nothing here is good enough, here is the next direction" is a valid answer.
