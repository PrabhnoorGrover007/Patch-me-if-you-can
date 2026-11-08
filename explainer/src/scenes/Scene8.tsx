// 110-120s: The Bug Gang in handcuffs, Vinny's moustache falls off, tagline card, team names.
import React from "react";
import { AbsoluteFill, interpolate, OffthreadVideo, spring, staticFile, useCurrentFrame, useVideoConfig } from "remotion";
import { AgentGranite, Bug } from "../characters/characters";
import { Stage, usePop } from "../components";
import { assets, R, TBD } from "../data";
import { body, C, comic } from "../theme";

export const Scene8: React.FC = () => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  // moustache drops with a bounce
  const drop = spring({ frame: frame - 45, fps, config: { damping: 6, stiffness: 140, mass: 0.7 } });
  const tip = interpolate(frame, [95, 112, 135, 150], [0, 1, 1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const card = usePop(150, 9);
  const line2 = usePop(172, 9);
  const teamPop = usePop(200, 14);
  const team = R.team?.length ? R.team.join("  ·  ") : TBD;
  const gang = [
    { color: "#ff8fa3", x: 820 },
    { color: C.vinny, x: 1070, vinny: true },
    { color: "#c7a6ff", x: 1320 },
    { color: "#9fe7ff", x: 1570 },
  ];

  return (
    <AbsoluteFill style={{ background: C.night }}>
      {assets.scene8 ? (
        <OffthreadVideo src={staticFile("clips/scene8.mp4")} />
      ) : (
        <Stage>
          {/* line-up wall */}
          <rect width={1920} height={1080} fill={C.navy2} />
          {Array.from({ length: 12 }, (_, i) => (
            <rect key={i} x={560} y={180 + i * 60} width={1300} height={4} fill={C.cream} opacity={0.18} />
          ))}
          <rect x={0} y={900} width={1920} height={180} fill="#0a0e24" />
          <rect y={900} width={1920} height={6} fill={C.amber} opacity={0.6} />
          <ellipse cx={1200} cy={300} rx={700} ry={420} fill={C.amber} opacity={0.035} />
          {gang.map((g, i) => (
            <Bug key={i} uid={`gang${i}`} x={g.x} y={905 + Math.sin(frame / 7 + i) * 4} scale={0.82} facing={-1} color={g.color}
              cuffs badge={g.vinny ? "MEDIUM" : undefined} moustache={!!g.vinny} moustacheDrop={g.vinny ? Math.min(drop, 1.15) : 0}
              antenna={!!g.vinny} blink={Math.sin(frame / 5)} mask={!g.vinny || frame < 45} />
          ))}
          <AgentGranite uid="a8" x={330} y={985} scale={0.95} tip={tip} armUp={tip} glow={1} magnifier={tip === 0} />
        </Stage>
      )}
      {/* tagline card */}
      <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", pointerEvents: "none" }}>
        {frame >= 150 && (
          <div style={{
            background: "rgba(7,10,26,0.9)", border: `6px solid ${C.amber}`, borderRadius: 36, padding: "40px 70px",
            textAlign: "center", transform: `scale(${0.4 + 0.6 * card}) rotate(${(1 - card) * 6}deg)`, opacity: Math.min(1, card * 1.5),
            boxShadow: `0 0 60px rgba(255,182,39,0.35)`,
          }}>
            <div style={{ fontFamily: comic, fontSize: 112, color: C.cream, letterSpacing: 3 }}>DON'T PATCH THEM ALL.</div>
            <div style={{ fontFamily: comic, fontSize: 112, color: C.amber, letterSpacing: 3, transform: `scale(${line2})` }}>PATCH THE ONES THAT FALL.</div>
            <div style={{ fontFamily: body, fontWeight: 800, fontSize: 40, color: C.teal, marginTop: 18, opacity: teamPop }}>{team}</div>
          </div>
        )}
      </AbsoluteFill>
      {frame < 146 && (
        <AbsoluteFill style={{ justifyContent: "flex-start", alignItems: "center", paddingTop: 60 }}>
          <div style={{ fontFamily: comic, fontSize: 120, color: C.amber, WebkitTextStroke: `3px ${C.ink}`, transform: `scale(${stampIn(frame)})` }}>CASE CLOSED.</div>
        </AbsoluteFill>
      )}
    </AbsoluteFill>
  );
};

// simple non-hook ease for the "CASE CLOSED" stamp (keeps hooks unconditional)
function stampIn(frame: number) {
  return interpolate(frame, [0, 10, 16], [2.2, 0.92, 1], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
}
