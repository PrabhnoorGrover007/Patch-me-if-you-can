// The full 2-minute video: every scene in order, plus optional voiceover and music.
import React from "react";
import { AbsoluteFill, Audio, Series, staticFile } from "remotion";
import { assets } from "./data";
import { Placeholder } from "./scenes/Placeholder";
import { Scene1 } from "./scenes/Scene1";
import { Scene2 } from "./scenes/Scene2";
import { Scene3 } from "./scenes/Scene3";
import { Scene8 } from "./scenes/Scene8";
import { FPS, SCENES } from "./theme";

export const SCENE_COMPONENTS: Record<string, React.FC> = {
  Scene1,
  Scene2,
  Scene3,
  Scene4: () => <Placeholder n={4} title="Evidence board: our main chart" />,
  Scene5: () => <Placeholder n={5} title="Detective line-up: CVSS vs EPSS vs us" />,
  Scene6: () => <Placeholder n={6} title="Shredding the leaked columns" />,
  Scene7: () => <Placeholder n={7} title="Live demo" />,
  Scene8,
};

export const Video: React.FC = () => (
  <AbsoluteFill style={{ background: "#070a1a" }}>
    <Series>
      {SCENES.map((s) => {
        const Comp = SCENE_COMPONENTS[s.id];
        return (
          <Series.Sequence key={s.id} durationInFrames={s.seconds * FPS} name={s.id}>
            <Comp />
          </Series.Sequence>
        );
      })}
    </Series>
    {assets.voiceover && <Audio src={staticFile("voiceover.mp3")} />}
    {assets.music && <Audio src={staticFile("music.mp3")} volume={0.15} loop />}
  </AbsoluteFill>
);
