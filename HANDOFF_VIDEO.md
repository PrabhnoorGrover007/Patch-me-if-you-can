# Handoff for Codex: the 2:30 video + the new dashboard features

Branch: `video-and-time-machine`. Read this file first, then `video/PLOT_2m30.md`.

## Who and what
- Project: **Patch Me If You Can**, Sheridan Datathon 2026, IBM "Before the Breach" track. Rank the 500 CVEs (of 72,670) most likely to be added to CISA KEV, without leakage.
- Harsh Shah handles the **video**. Teammates (Zahan, Prabhnoor) own the data/ML pipeline and the web app.
- Harsh is making the cartoon clips in **Higgsfield**. Your job is to help assemble the **exact 2:30 master** (Remotion in `explainer/`, or a cut list for Higgsfield/CapCut) and record the dashboard tour.

## Hard rules
1. **Never invent, round up or guess a number.** Every number on screen or in the voiceover must come from `findings.md`, `outputs/validation_results.json`, `app/src/data/*.json` or the app itself. If a value is missing, show `[TBD]` and say so.
2. If the data says something different from the story, **change the story**. The finding must be true.
3. No real logos, movie footage, music or actor names. Keep the bank fictional. "IBM Bank" signage is undecided (it may look like an endorsement); "Granite Bank" is the safer default.
4. Never tune anything on the live CISA KEV list; it is the judges' answer key.
5. Don't commit the raw dataset (`data/`, ~850 MB) or big video files.
6. Don't push to `main`. Work on this branch or a new one and open a PR.

## Run the dashboard (no raw data needed on this branch)
```powershell
cd app
npm install
npx next dev -p 3001        # http://localhost:3001
```
`app/src/data/cves.json`, `meta.json` and `timemachine.json` are committed on this branch only, so the app runs without the raw CSVs. On `main` they are gitignored and rebuilt with `npm run data` (needs `IBM_dataset/data/*.csv`) and `python timemachine.py --data-dir data` (needs `outputs/train.csv` from `prepare_data.py`).

## The 8 tabs (what the video tours)
| Tab | Route | What it shows |
|---|---|---|
| Dashboard | `/` | Top 500 queue, stat cards, quick-wins matrix, "why it ranks here" panel |
| **Time Machine** (new) | `/time-machine` | Replays 2025: two 500-square lists, squares turn red when CISA confirms an attack. End: our model 18, CVSS 10 |
| **Patch Budget** (new) | `/patch-budget` | Slider for how many bugs you can fix; attacks stopped per method; "CVSS needs 500 for 10, our model needs 73 (85% less work)" |
| **Beat the Model** (new) | `/beat-the-model` | 5-round game: 4 real 2025 bugs, 1 later exploited. You vs the model vs highest CVSS |
| Risk trends | `/analytics` | Open risk and mean time to remediate (empty until cards are on the board) |
| Remediation | `/queue` | Kanban patch board (stored in `app/.data/remediation.json`) |
| Upload | `/upload` | Validates a submission CSV |
| Chat | `/chat` | AI analyst. Shows "Offline heuristic" unless keys are set. For the video it must say **IBM Granite**: set `WATSONX_API_KEY` + `WATSONX_PROJECT_ID` in `app/.env.local` and leave `GEMINI_API_KEY` empty |

New feature code: `timemachine.py` (export, refuses to run if its hit counts differ from `validation_results.json`), `app/src/lib/timemachine.ts`, `app/src/components/{TimeMachine,PatchBudget,BeatTheModel}.tsx`, `app/src/app/{time-machine,patch-budget,beat-the-model}/page.tsx`.

## Verified numbers for the video
| Claim | Value | Source |
|---|---|---|
| Scoreboard size / submission | 72,670 / 500 | app dashboard, `validation_results.json` |
| 2025 test set | 39,859 CVEs, 48 later exploited | `validation_results.json` |
| Attacks caught in top 500 (2025 test) | our model 18 · exploit code then EPSS 20 · EPSS 13 · CVSS 10 | `validation_results.json` |
| Same share as the real top 500 (top 274) | our model 17 · exploit-then-EPSS 15 · CVSS 5 | `validation_results.json` |
| Effort: CVSS's 10 catches | CVSS needs 500 patches, our model 73 (85% less) | Patch Budget page (ranks in `timemachine.json`) |
| Beat the Model, 4-suspect rounds | model 35.9%, highest CVSS 19.5%, blind guess 25% | 100,000 simulated rounds over `timemachine.json` |
| Login bypass | 1,087 CVEs, 12 exploited, 7.8× | `outputs/train.csv` / `findings.md` |
| Remote code execution | 7,311 CVEs, 27 exploited, 2.6× | same |
| Cross-site scripting | 14,149 CVEs, 5 exploited, 0.2× | same |
| Denial of service | 4,448 CVEs, 0 exploited | `outputs/train.csv` (`kw_dos`) |
| WordPress plugins | 0 of 8,149 exploited | `findings.md` |

Be honest about one thing: at 500, the simple "exploit code, then EPSS" rule (20) beats our model (18). Don't claim "best method" in the video. Claims that hold: beats CVSS and EPSS at every size shown, and leads every method up to about 300 patches.

## The video
The full plan is in **`video/PLOT_2m30.md`**: the timeline (exactly 150 s = 4,500 frames at 30 fps, 1920×1080), scenes A–H, the ElevenLabs narration script with file names, start times and word limits, and the dashboard recording checklist.

Asset file names expected for the master:
- Higgsfield: `clip-A.mp4` `clip-B.mp4` `clip-C.mp4` `clip-D.mp4` `clip-F.mp4` `clip-G.mp4` `clip-H.mp4`
- Dashboard: `tab-E1-dashboard.mp4` … `tab-E8-upload.mp4`
- Voice: `vo-B.mp3` `vo-D.mp3` `vo-E1.mp3` … `vo-E8.mp3`, `harsh-A.mp3` `zahan-A.mp3` `harsh-C.mp3` `zahan-C.mp3` `harsh-F.mp3` `zahan-H.mp3` `harsh-H.mp3`
- Music: `music.mp3` (royalty-free, under the voice at about 15%)

`explainer/` is the existing Remotion project (Remotion 4.0.537, React 18). It has an earlier 2:00 cartoon (scenes 1–3, 8). The new master should be a **new composition at exactly 4,500 frames**, with one `<Sequence>` per slot in `PLOT_2m30.md`. Each clip is trimmed to its slot, and a missing file shows a labelled placeholder so the length never changes. Run with `cd explainer && npm install && npm run preview`.

## Open items
- [ ] Harsh: Higgsfield clips A, B, C, D, F, G, H (reference photos of Harsh and Zahan; confirm Zahan agrees to his likeness and voice being used)
- [ ] Team: set up IBM Granite keys before recording the Chat tab
- [ ] Team: fill the patch board (about 8 cards, a few Done) before recording Remediation/Risk trends
- [ ] Decide on "IBM Bank" vs "Granite Bank" signage
- [ ] Record the 8 dashboard clips (automate with Playwright at 1920×1080 if possible)
- [ ] Build the 4,500-frame master composition
- [ ] Team decision, not video: the submitted `top500.csv` uses the model that scores 18 at 500; the exploit-code rule scores 20
