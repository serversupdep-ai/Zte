# Dead ends — NEVER retry these

## Network routes
- **Telegram file downloads**: t.me document deeplinks are browser-session-bound.
  A fresh deeplink + cookie jar + referer STILL returns the 6,391-B
  desktop.telegram.org redirect. (t.me PAGE fetches work fine.)
- **dr-bios.com attachments**: 403 login wall (every thread).
- **badcaps.net attachments**: premium-supporter wall.
- **vinafix.com attachments**: paywall.
- **bios-fix.com**: login wall (the "pay by transaction ID" 8FC8 service).
- **indiafix.in direct**: CAPTCHA — use Wayback `id_` snapshots instead.
- **Akamai on dell.com pages**: relay gets blocked — fetch pages locally,
  use the relay ONLY for direct dl.dell.com file URLs.
- **linkvertise / cuty.io interstitials**: hCaptcha, dead.
- **alisaler Google Drive links**: quota-exceeded.
- **arctic-shift body search**: times out server-side on suffix queries
  (subreddit-filtered too). Threaded/comment-tree endpoints DO work.

## People / services
- **Reddit code-givers** (r/Dell 1mni7p9 thread): ALL EC-era requests declined —
  "beyond our current ability… no known way without a bios chip flash" —
  including 9B1N0R3-CF1B "dell latitude 3090" (our exact model+suffix).
  Legacy E7A8 requests were answered. A proprietary generator exists but is
  not public; its holder confirms EC-era is out of reach.
- **DellBIOSTools** (github chromebreakerdev, V2.6 Aug-2026, audited): the
  Password Generator tab = legacy MD5 math only; for 8FC8/CF1B it directs to
  its BIOS Unlocker tab = dump pattern-patcher. No EC-era generation exists.
- **bios-pw.org**: legacy suffixes only.
- **Paid sellers** (ThienBui $15–25 patch, aditya11ttt ₹7,500, passwords247,
  pwd4bios): per-machine service. None sells the algorithm.

## Technical
- **§10 legacy-style approach for CF1B**: retracted — CF1B is not MD5-derived.
- **Offline inversion of tag→code or challenge→response pairs**: impossible (§11.7).
- **3420/3520 1.13.3 DUB**: PFS sections opaque/encrypted; LZMA-alone sweep
  found nothing. uefi_firmware PFSFile raises TypeError on 1.6.0 DUB too —
  always use extract_pw_modules.find_dub + the PHCM regex.
- **FLMAP0 table at 0x410**: garbage (the real one is at 0x400).
- **Thumb-2 census on sealed PHCM bodies**: meaningless (ciphertext).

## Infrastructure
- `gh workflow run`: bot gets 403 — trigger the fetch relay by pushing to
  relay/ only. Bot cannot post issue comments.
- Relay idempotency: manifests prevent refetch — `git rm -r` the target dir
  first to force. Stagger triggers (concurrent runs lose the commit push race).
