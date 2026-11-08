// 0-12s: Officer CVSS checks severity badges. Vinny (badge: MEDIUM) strolls past into the vault.
import React from "react";
import { AbsoluteFill, interpolate, OffthreadVideo, staticFile, useCurrentFrame } from "remotion";
import { Bug, OfficerCVSS } from "../characters/characters";
import { Bank, Bubble, Camera, Caption, NightCity, Stage, usePop } from "../components";
import { assets } from "../data";
import { C, comic } from "../theme";

export const Queue: React.FC<{ frame: number; frontHop: number }> = ({ frame, frontHop }) => {
  const q = [
    { badge: "CRITICAL", color: "#ff8fa3", badgeColor: C.red },
    { badge: "HIGH", color: "#c7a6ff", badgeColor: C.amber },
    { badge: "LOW", color: "#ffd08a", badgeColor: C.teal },
    { badge: "HIGH", color: "#9fe7ff", badgeColor: C.amber },
  ];
  return (
    <g>
      {q.map((b, i) => {
        const hop = i === 0 ? frontHop : 0;
        return (
          <Bug key={i} uid={`q${i}`} x={1130 + i * 190 - hop * 120} y={962 - Math.abs(Math.sin(hop * Math.PI)) * 60 + Math.sin(frame / 9 + i) * 3}
            scale={0.55} facing={-1} color={b.color} badge={b.badge} badgeColor={b.badgeColor} walk={frame / 8 + i} mask={false} />
        );
      })}
    </g>
  );
};

export const Zzz: React.FC<{ frame: number; x: number; y: number }> = ({ frame, x, y }) => (
  <g>
    {[0, 1, 2].map((i) => {
      const t = ((frame + i * 25) % 75) / 75;
      return (
        <text key={i} x={x + t * 60 + i * 10} y={y - t * 120} fontFamily={comic} fontSize={40 + i * 10} fill={C.teal} opacity={1 - t}>Z</text>
      );
    })}
  </g>
);

export const Scene1: React.FC = () => {
  const frame = useCurrentFrame();
  const stamp1 = interpolate(frame, [30, 40, 48, 60], [0, 1, 1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const stamp2 = interpolate(frame, [190, 200, 208, 220], [0, 1, 1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const frontHop = usePop(62, 14);
  // Vinny tiptoes from off-screen right, behind the queue, to the vault
  const vx = interpolate(frame, [190, 320], [2080, 940], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const vanish = interpolate(frame, [318, 345], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const doorOpen = interpolate(frame, [300, 320, 345, 360], [0, 0.35, 0.35, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{ background: C.night }}>
      {assets.scene1 ? (
        <OffthreadVideo src={staticFile("clips/scene1.mp4")} />
      ) : (
        <Camera>
          <Stage lift={120}>
            <NightCity />
            <Bank x={560} open={doorOpen} />
            {frame >= 190 && vanish > 0 && (
              <Bug uid="vinny" x={vx} y={900 + Math.sin(frame / 4) * 4} scale={0.75 * (0.4 + 0.6 * vanish)} facing={-1}
                badge="MEDIUM" moustache antenna blink={Math.sin(frame / 6)} walk={frame / 5} />
            )}
            <Queue frame={frame} frontHop={frontHop} />
            <OfficerCVSS uid="g1" x={640} y={950} scale={0.95} stamp={Math.max(stamp1, stamp2)} droop={0.5 + 0.1 * Math.sin(frame / 25)} bob={Math.sin(frame / 18) * 3} />
            <Zzz frame={frame} x={700} y={470} />
            <Bubble x={180} y={180} w={640} h={140} text="CRITICAL? FRONT OF THE LINE!" from={25} to={175} tx={560} ty={420} size={50} />
            <Bubble x={180} y={180} w={560} h={140} text="MEDIUM? EH... LATER." from={185} to={355} tx={560} ty={420} size={54} />
          </Stage>
        </Camera>
      )}
      <Caption text="Every year, thousands of bugs line up at the door." from={0} to={172} />
      <Caption text="Only a few are criminals." from={176} to={360} color={C.amber} />
    </AbsoluteFill>
  );
};
