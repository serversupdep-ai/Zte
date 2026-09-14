# Dell BIOS Suffix Cheat Sheet

## Suffixes WITH keygen (password computable from service tag)

| Suffix | Machine era | Notes |
|---|---|---|
| 595B | ~2005-2008 | oldest family |
| D35B | ~2006-2009 | |
| 2A7B | ~2008-2011 | |
| A95B | ~2008-2011 | use 595B algorithm |
| 1D3B | ~2010-2012 | |
| 1F5A | ~2011-2013 | |
| 1F66 | ~2011-2013 | test vector: DELLSUX → qHXaL0ntli6Gu4c0 |
| 6FF1 | ~2012-2015 | known bug — use BF97 instead |
| BF97 | ~2012-2016 | |
| E7A8 | ~2019-2022 | newest keygen-able family, gives 2 candidates |

Generate: `python3 tools/dell_keygen.py SERVICETAG-SUFFIX`
(also works: bios-pw.org online, DellBIOSTools GUI)

After typing the code: press **Ctrl+Enter+Enter** on some models.

## Suffixes with NO keygen (firmware-verified — no code can exist)

| Suffix | Machine era | Only way |
|---|---|---|
| 8FC8 | ~2017-2022 | dump + patch, or Dell support |
| CF1B | ~2023+ | dump + patch, or Dell support |
| FC1B | ~2023+ (same family as CF1B) | dump + patch, or Dell support |

For these: `python3 tools/dell_fc1b_unlock.py dump.bin` after dumping the
flash chip with a CH341A programmer. Zeroes the 00FCAA (system) and
00FDAA (admin) password entries. Dell NVRAM stores **four redundant
password flags** — the scan finds and zeroes all of them.

## What lives where (this workspace)

- `agent-me/knowledge/` — the agent's brain (Markdown, hot-reloads)
- `agent-me/tools/dell_keygen.py` — legacy suffix keygen
- `agent-me/tools/dell_fc1b_unlock.py` — CF1B/FC1B/8FC8 dump patcher
- `agent-me/tools/test_fc1b_tools.py` — self-tests
- `agent-me/knowledge/case-cvzkkd3-cf1b.md` — active case (Precision 3640 Tower)

## The methodology (what you learned)

1. agent-me = agent framework (FastAPI + React + Markdown knowledge)
2. Clone the public tool repo that contains the algorithms
3. Extract the pure algorithm code into a standalone script
4. Write the knowledge into knowledge/*.md — the agent answers from it
5. Test everything (public vectors + synthetic dumps)
6. Be honest about limits: no keygen = no keygen, say so

Only unlock machines you own or are authorized to service.
