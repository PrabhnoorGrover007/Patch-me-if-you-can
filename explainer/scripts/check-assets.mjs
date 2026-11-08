// Looks in public/ for the optional outside files and writes src/assets.json,
// so the video knows whether to play a real clip or draw the cartoon version.
import { existsSync, writeFileSync } from "node:fs";

const files = {
  scene1: "public/clips/scene1.mp4",
  scene2: "public/clips/scene2.mp4",
  scene8: "public/clips/scene8.mp4",
  demo: "public/demo.mp4",
  voiceover: "public/voiceover.mp3",
  music: "public/music.mp3",
};
const found = Object.fromEntries(Object.entries(files).map(([k, p]) => [k, existsSync(p)]));
writeFileSync("src/assets.json", JSON.stringify(found, null, 2) + "\n");
console.log("Outside files found:", found);
