// 25-35s: Smoke clears, Agent Granite steps in and tips his hat. Title card.
import React from "react";
import { AbsoluteFill, interpolate, random, useCurrentFrame } from "remotion";
import { AgentGranite } from "../characters/characters";
import { Caption, NightCity, Stage, usePop } from "../components";
import { body, C, comic } from "../theme";

export const Scene3: React.FC = () => {
  const frame = useCurrentFrame();
  const rise = usePop(28, 11);
  const tip = interpolate(frame, [95, 115, 140, 160], [0, 1, 1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const glow = interpolate(frame, [60, 90], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" }) * (0.85 + 0.15 * Math.sin(frame / 6));
  const title = usePop(150, 7);
  const sub = usePop(175, 14);
  const shake = frame >= 150 && frame < 162 ? Math.sin(frame * 3) * (162 - frame) * 1.2 : 0;

  return (
    <AbsoluteFill style={{ background: C.night }}>
      <Stage>
        <g transform={`translate(${shake} 0)`}>
          <NightCity tint="rgba(7,10,26,0.55)" />
          {/* spotlight */}
          <polygon points="860,0 1060,0 1260,1080 660,1080" fill={C.teal} opacity={0.07 + 0.05 * glow} />
          <ellipse cx={960} cy={985} rx={260} ry={34} fill={C.teal} opacity={0.15 * glow} />
          <AgentGranite uid="a3" x={960} y={1000 + (1 - rise) * 650} scale={1.0} tip={tip} armUp={tip} glow={glow} />
          {/* smoke */}
          {Array.from({ length: 16 }, (_, i) => {
            const t = interpolate(frame, [0 + i * 2, 120 + i * 2], [0, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
            const ang = random(`a${i}`) * Math.PI * 2;
            const dist = 80 + random(`d${i}`) * 420;
            return (
              <circle key={i} cx={960 + Math.cos(ang) * dist * t} cy={760 + Math.sin(ang) * dist * 0.5 * t - t * 120}
                r={90 + t * 220 * (0.6 + random(`r${i}`) * 0.6)} fill="#8e7cc3" opacity={0.55 * (1 - t)} />
            );
          })}
          {/* title card */}
          {frame >= 150 && (
            <g transform={`translate(960 215) scale(${0.3 + 0.7 * title}) rotate(${(1 - title) * -10})`}>
              <text x={8} y={10} textAnchor="middle" fontFamily={comic} fontSize={168} fill={C.teal} letterSpacing={4}>PATCH ME IF YOU CAN</text>
              <text x={0} y={0} textAnchor="middle" fontFamily={comic} fontSize={168} fill={C.amber} stroke={C.ink} strokeWidth={5} letterSpacing={4}>PATCH ME IF YOU CAN</text>
            </g>
          )}
          {frame >= 175 && (
            <text x={960} y={315} textAnchor="middle" fontFamily={body} fontWeight={800} fontSize={40} fill={C.cream}
              opacity={sub} letterSpacing={6}>IBM · BEFORE THE BREACH · SHERIDAN DATATHON 2026</text>
          )}
        </g>
      </Stage>
      <Caption text="So we asked: can we catch them before the heist?" from={0} to={146} />
    </AbsoluteFill>
  );
};
