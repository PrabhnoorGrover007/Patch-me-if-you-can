import React from "react";
import { Composition } from "remotion";
import { missingValues } from "./data";
import { FPS, H, SCENES, W } from "./theme";
import { SCENE_COMPONENTS, Video } from "./Video";

const missing = missingValues();
if (missing.length) {
  // Shows in the terminal / studio console so nobody is surprised by a [TBD] on screen.
  console.warn(`[results.json] missing values shown as [TBD]: ${missing.join(", ")}`);
}

const total = SCENES.reduce((t, s) => t + s.seconds, 0) * FPS;

export const Root: React.FC = () => (
  <>
    <Composition id="Explainer" component={Video} durationInFrames={total} fps={FPS} width={W} height={H} />
    {SCENES.map((s) => (
      <Composition key={s.id} id={s.id} component={SCENE_COMPONENTS[s.id]} durationInFrames={s.seconds * FPS} fps={FPS} width={W} height={H} />
    ))}
  </>
);
