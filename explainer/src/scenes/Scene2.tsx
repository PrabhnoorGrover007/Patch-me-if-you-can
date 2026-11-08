// 12-25s: Alarm. Vinny escapes with a money bag while the guard keeps stamping badges.
import React from "react";
import { AbsoluteFill, interpolate, OffthreadVideo, staticFile, useCurrentFrame } from "remotion";
import { Bug, OfficerCVSS } from "../characters/characters";
import { Bank, Bubble, Camera, Caption, NightCity, Stage, usePop } from "../components";
import { assets } from "../data";
import { C, comic } from "../theme";
import { Queue, Zzz } from "./Scene1";

export const Scene2: React.FC = () => {
  const frame = useCurrentFrame();
  const pulse = Math.max(0, Math.sin(frame / 5));
  const emerge = usePop(10, 10);
  const vx = interpolate(frame, [40, 210], [940, 2250], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const running = frame >= 40;
  const stamp = (Math.sin(frame / 7) + 1) / 2;
  const burst = usePop(4, 7);
  const burstOut = interpolate(frame, [70, 85], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });

  return (
    <AbsoluteFill style={{ background: C.night }}>
      {assets.scene2 ? (
        <OffthreadVideo src={staticFile("clips/scene2.mp4")} />
      ) : (
        <Camera from={1.04} to={1.0}>
          <Stage lift={120}>
            <NightCity />
            <Bank x={560} open={1} wheel={frame * 4} />
            {/* rooftop siren */}
            <g>
              <rect x={915} y={140} width={50} height={34} rx={6} fill="#333a55" stroke={C.ink} strokeWidth={4} />
              <path d="M 918 142 Q 940 92 962 142 Z" fill={C.red} stroke={C.ink} strokeWidth={4} opacity={0.6 + 0.4 * pulse} />
              <g transform={`rotate(${frame * 9} 940 125)`} opacity={0.35}>
                <polygon points="940,125 1500,40 1500,210" fill={C.red} />
                <polygon points="940,125 380,40 380,210" fill={C.red} />
              </g>
            </g>
            {frame >= 10 && (
              <Bug uid="vinny2" x={vx} y={900 - Math.abs(Math.sin(frame / 4)) * (running ? 40 : 0)} scale={0.3 + 0.45 * emerge} facing={1}
                badge="MEDIUM" moustache antenna bag blink={Math.sin(frame / 3)} walk={frame / 2.2} />
            )}
            <Queue frame={frame + 360} frontHop={1} />
            <OfficerCVSS uid="g2" x={640} y={950} scale={0.95} stamp={stamp} droop={0.68} bob={Math.sin(frame / 18) * 3} />
            <Zzz frame={frame} x={700} y={470} />
            <Bubble x={160} y={190} w={520} h={130} text="NEXT... ZZZ" from={220} to={385} tx={560} ty={420} size={56} />
            {frame < 85 && (
              <g opacity={burstOut} transform={`translate(1500 330) scale(${burst}) rotate(-8)`}>
                <polygon points="0,-150 40,-60 140,-90 80,-10 160,50 50,60 40,160 -20,70 -120,130 -80,30 -170,-20 -70,-50 -110,-140 -20,-80" fill={C.amber} stroke={C.ink} strokeWidth={8} />
                <text x={0} y={30} textAnchor="middle" fontFamily={comic} fontSize={96} fill={C.red} stroke={C.ink} strokeWidth={3}>ALARM!</text>
              </g>
            )}
          </Stage>
        </Camera>
      )}
      <AbsoluteFill style={{ background: C.red, opacity: 0.16 * pulse, mixBlendMode: "screen" }} />
      <Caption text="Security teams patch by severity score." from={0} to={190} />
      <Caption text="Attackers don't care about severity." from={194} to={390} color={C.amber} />
    </AbsoluteFill>
  );
};
