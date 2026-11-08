import { loadFont as loadBangers } from "@remotion/google-fonts/Bangers";
import { loadFont as loadInter } from "@remotion/google-fonts/Inter";

export const comic = loadBangers().fontFamily;
export const body = loadInter("normal", { weights: ["600", "800", "900"], subsets: ["latin"] }).fontFamily;

export const C = {
  night: "#070a1a",
  navy: "#0b1026",
  navy2: "#141b3d",
  navy3: "#1f2a5c",
  teal: "#2de2e6",
  amber: "#ffb627",
  red: "#ff3b4e",
  cream: "#f4f1e8",
  ink: "#0a0d1c",
  skin: "#f2c48d",
  guard: "#3557d4",
  vinny: "#7ed957",
  rock: "#8d939e",
  rockDark: "#5f6570",
  coat: "#c9a36b",
  coatDark: "#9c7a48",
};

export const FPS = 30;
export const W = 1920;
export const H = 1080;

// Scene lengths in seconds (must add up to 120)
export const SCENES = [
  { id: "Scene1", seconds: 12 },
  { id: "Scene2", seconds: 13 },
  { id: "Scene3", seconds: 10 },
  { id: "Scene4", seconds: 30 },
  { id: "Scene5", seconds: 20 },
  { id: "Scene6", seconds: 15 },
  { id: "Scene7", seconds: 10 },
  { id: "Scene8", seconds: 10 },
] as const;
