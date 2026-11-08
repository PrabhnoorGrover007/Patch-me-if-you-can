# Patch Me If You Can: 2:30 video plan

**Length: exactly 2:30** (150.0 s = 4,500 frames at 30 fps, 1920×1080).
The final cut is assembled in Remotion, which forces the exact length. Every clip gets trimmed to its slot.

Voice: an **ElevenLabs narrator** carries the dashboard tour. **Harsh and Zahan** speak the short character lines (record them yourselves, or use ElevenLabs voice clones of your own voices; Zahan must agree to his face and voice being used).

Every number below comes from the team's data (`findings.md`, `outputs/validation_results.json`, `outputs/train.csv`, the app). Source is noted next to each one. Don't change a number without changing its source.

---

## Timeline (adds up to 150 s)

| # | Time | Len | Scene | Made with |
|---|---|---|---|---|
| A | 0:00–0:10 | 10 s | Viewing room: Zahan giggling at the heist | Higgsfield |
| B | 0:10–0:30 | 20 s | The heist: Officer CVSS waves 4 bugs in | Higgsfield |
| C | 0:30–0:37 | 7 s | Cliffhanger: movie freezes before the vault | Higgsfield + freeze frame |
| D | 0:37–0:45 | 8 s | Professors' lab: the evidence board | Higgsfield + Remotion graphic |
| E1 | 0:45–0:57 | 12 s | Tab: **Dashboard** | screen recording |
| E2 | 0:57–1:15 | 18 s | Tab: **Time Machine** (hero moment) | screen recording |
| E3 | 1:15–1:25 | 10 s | Tab: **Patch Budget** | screen recording |
| E4 | 1:25–1:35 | 10 s | Tab: **Beat the Model** | screen recording |
| E5 | 1:35–1:43 | 8 s | Tab: **Chat** (Granite answer) | screen recording |
| E6 | 1:43–1:49 | 6 s | Tab: **Remediation** board | screen recording |
| E7 | 1:49–1:54 | 5 s | Tab: **Risk trends** | screen recording |
| E8 | 1:54–1:59 | 5 s | Tab: **Upload** check | screen recording |
| F | 1:59–2:07 | 8 s | Dashboard row morphs into Vinny; movie resumes | Higgsfield + Remotion transition |
| G | 2:07–2:22 | 15 s | The capture: chase, blocked exit, net | Higgsfield |
| H | 2:22–2:30 | 8 s | Final joke + title card | Higgsfield + Remotion title |

During E1–E8, the screen recordings sit inside a monitor in the professors' lab for the first second, then go full-screen. Small cut-ins of cartoon Harsh/Zahan pointing are optional.

---

## Why the plot is true

The cliffhanger asks "which bug do we stop first?" The data gives a clear answer (`outputs/train.csv`, 78,287 CVEs, lift = times more likely than average to be exploited):

| Burglar | Bug type | CVEs | Later exploited | Lift |
|---|---|---|---|---|
| **Vinny** | Login (authentication) bypass | 1,087 | 12 | **7.8×** |
| **Rex** | Remote code execution | 7,311 | 27 | **2.6×** |
| **Xena** | Cross-site scripting | 14,149 | 5 | **0.2×** |
| **Dee** | Denial of service | 4,448 | **0** | **0×** |

So the heroes go after **Vinny first, then Rex**. Xena and Dee are mostly noise.

---

## Scene by scene

### A. Viewing room (0:00–0:10)
Zahan watches a cartoon heist on a big monitor, laughing. Harsh walks in.
- **HARSH:** "Hey Zahan, what are you watching?"
- **ZAHAN** (grinning): "The worst security guard in the world."

### B. The heist (0:10–0:30)
Camera pushes into the monitor. A fictional bank at night. Officer CVSS stares at his clipboard, stamping badges. Four bug burglars sneak past, each with a name tag shown for about 1 second:
Vinny (Login Bypass) · Rex (Remote Code) · Xena (Cross-Site Scripting) · Dee (Denial of Service).
The guard yawns and waves them inside. They tiptoe toward the vault.
- **NARRATOR** (ElevenLabs, from 0:18): see VO-B.

### C. Cliffhanger (0:30–0:37)
The bugs reach the vault door. **Freeze frame**, with a pause icon and VHS wobble. Cut back to the room.
- **HARSH:** "Wait. Which of those bugs should we stop first?"
- **ZAHAN** (stops laughing): "Let's check the evidence."

### D. Professors' lab: evidence board (0:37–0:45)
Match-cut: Harsh and Zahan in lab coats in a cartoon cyber lab. They slap 4 mugshots on a board. A Remotion graphic overlays the real lifts from the table above, with bars growing: Vinny 7.8× · Rex 2.6× · Xena 0.2× · Dee 0×.
- **NARRATOR:** VO-D.

### E1–E8. Dashboard tour (0:45–1:59)
Real screen recordings only. No invented interface text or numbers. See the recording checklist below.

### F. Back into action (1:59–2:07)
On the dashboard, a click on a login-bypass row. The row glows and morphs into Vinny on the frozen movie frame. Unpause.
- **HARSH:** "Vinny first. Then Rex."

Harsh, Zahan and Agent Granite walk into the bank. Granite points; the team splits up.

### G. The capture (2:07–2:22)
One continuous chase: the bugs spot the team, run for the exit, find it blocked by Agent Granite, turn back, and a comic net drops on them. The heroes stay outside the net. The data bag is recovered. Officer CVSS finally looks up from his clipboard, baffled.
No dialogue. Music and sound effects only.

### H. Final joke + title (2:22–2:30)
Back in the viewing room.
- **ZAHAN:** "Okay. That ending was better."
- **HARSH:** "You're welcome."

Title card (2:26–2:30): **PATCH ME IF YOU CAN**, then *Don't patch them all. Patch the ones that fall.*, then team names.

---

## ElevenLabs narrator script

One file per line, named as below, so each drops into its exact slot. The word count in brackets is the most that fits at a normal pace. If a file runs long, raise ElevenLabs **speed** (up to about 1.1) or cut words. Never stretch the audio.

| File | Starts | Max | Text | Source |
|---|---|---|---|---|
| `vo-B.mp3` | 0:18 | 10 s, ~22 words | "Security teams patch by severity score. But attackers don't care about severity. They care about what's easy to break." | concept |
| `vo-D.mp3` | 0:38 | 7 s, ~17 words | "Login bypass bugs get exploited almost eight times more than average. Denial of service? Zero out of four thousand." | train.csv: 7.8×, 0 of 4,448 |
| `vo-E1.mp3` | 0:45 | 12 s, ~28 words | "This is Patch Me If You Can. Out of 72,670 new vulnerabilities, it picks the 500 to fix first, and shows exactly why each one made the list." | app dashboard |
| `vo-E2.mp3` | 0:57 | 18 s, ~42 words | "But does it work? Meet the Time Machine. We trained only on 2024, then replayed 2025. Every red square is a bug hackers really used. Our list caught 18. Patching by severity caught 10." | validation_results.json: hits@500 = 18 vs 10 |
| `vo-E3.mp3` | 1:15 | 10 s, ~23 words | "Patching by severity takes 500 fixes to stop 10 attacks. Our model stops the same 10 with just 73. That's 85% less work." | Patch Budget page: 73 vs 500 |
| `vo-E4.mp3` | 1:25 | 10 s, ~23 words | "Think you can do better? Four suspects, one real attacker. Picking the highest severity is right one time in five. That's worse than guessing." | 100k simulated rounds: 19.5% vs 25% guess |
| `vo-E5.mp3` | 1:35 | 8 s, ~18 words | "Ask IBM Granite about any vulnerability, and it answers using only what was known at the time." | Chat tab, only if Granite is set up (see below) |
| `vo-E6.mp3` | 1:43 | 6 s, ~13 words | "Drag fixes across the patch board, from to-do to done." | Remediation tab |
| `vo-E7.mp3` | 1:49 | 5 s, ~11 words | "Risk trends show the danger dropping as fixes land." | Risk trends tab |
| `vo-E8.mp3` | 1:54 | 5 s, ~11 words | "And every submission is checked before it ships." | Upload tab |

**Narrator settings to try:** a calm, warm documentary voice. Stability about 50, similarity about 75, style 0 to 15. Keep the same voice and settings for every file so it sounds like one take.

Character lines (A, C, F, H) are separate files: `harsh-A.mp3`, `zahan-A.mp3`, `harsh-C.mp3`, `zahan-C.mp3`, `harsh-F.mp3`, `zahan-H.mp3`, `harsh-H.mp3`.

---

## Dashboard recording checklist (E1–E8)

Record at **1920×1080**, browser zoom **125%** so text is readable on a projector, mouse moving slowly. Record each tab as its own clip, at least 3 seconds longer than its slot.

**Before recording:**
1. **Set up IBM Granite** in `app/.env.local` (`WATSONX_API_KEY`, `WATSONX_PROJECT_ID`) and leave `GEMINI_API_KEY` empty, so the chat badge says **"IBM Granite"**, not "Offline heuristic" or "Google Gemini". If Granite isn't working, cut VO-E5's Granite claim.
2. **Fill the patch board.** Add about 8 CVEs from the dashboard, move 3 to In progress and 2 to Done. Otherwise Remediation and Risk trends show empty charts.
3. Have a teammate's real submission CSV ready for the Upload tab.

| Clip | What to do on screen |
|---|---|
| E1 Dashboard | Scroll from the 4 stat cards to the queue, click row #1, and let the "Why it ranks here" panel show |
| E2 Time Machine | Press **Play 2025** at 8× speed, hover a red square near the end, and end on the final counters |
| E3 Patch Budget | Start at 500, show the "85% less work" sentence, then slide down to 73 |
| E4 Beat the Model | Pick a card, the reveal shows the labels, then go to the next round |
| E5 Chat | Click "Why is this ranked so high?" and let the IBM Granite answer appear |
| E6 Remediation | Drag one card from In progress to Done |
| E7 Risk trends | A slow pan across the charts |
| E8 Upload | Drop the CSV and show the green checks |

---

## Production rules (from the brief)
- No subtitles, repeated shots, slowed footage, static reference sheets or long roster cards. Name tags last about 1 second.
- Generate each scene as its own Higgsfield shot (A, B, C, D, F, G, H), not one long generation.
- Keep the **bank fictional**. Avoid real logos. Spelling "IBM Bank" on screen can look like an IBM endorsement, so a safer sign is "Granite Bank" or "Data Bank". Decide as a team.
- No real movie footage, logos, music or actor names.
- Reference photos: one clear, front-facing, well-lit photo each of Harsh and Zahan.
