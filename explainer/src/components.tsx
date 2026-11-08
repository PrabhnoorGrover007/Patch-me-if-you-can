import React from "react";
import { AbsoluteFill, interpolate, random, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { body, C, comic } from "./theme";

/** Pop-in helper: bouncy 0 -> 1 starting at `from`. */
export function usePop(from: number, damping = 9) {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - from, fps, config: { damping, stiffness: 120, mass: 0.8 } });
}

/** Big bold caption bar at the bottom, so the video works with sound off. */
export const Caption: React.FC<{ text: string; from: number; to: number; color?: string }> = ({ text, from, to, color = C.cream }) => {
  const frame = useCurrentFrame();
  const pop = usePop(from, 12);
  if (frame < from || frame >= to) return null;
  const out = interpolate(frame, [to - 8, to], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  return (
    <AbsoluteFill style={{ justifyContent: "flex-end", alignItems: "center", paddingBottom: 56, pointerEvents: "none" }}>
      <div
        style={{
          fontFamily: body, fontWeight: 900, fontSize: 62, lineHeight: 1.15, color, textAlign: "center",
          maxWidth: 1600, padding: "18px 40px", borderRadius: 22,
          background: "rgba(7,10,26,0.82)", border: `4px solid ${C.teal}`,
          boxShadow: `0 0 30px rgba(45,226,230,0.35)`,
          transform: `translateY(${(1 - pop) * 60}px) scale(${0.9 + pop * 0.1})`, opacity: Math.min(pop * 1.4, 1) * out,
        }}
      >
        {text}
      </div>
    </AbsoluteFill>
  );
};

/** Comic speech bubble (SVG units). Tail points down-left to (tx, ty). */
export const Bubble: React.FC<{ x: number; y: number; w: number; h: number; text: string; from: number; to: number; tx: number; ty: number; size?: number }> = ({ x, y, w, h, text, from, to, tx, ty, size = 54 }) => {
  const frame = useCurrentFrame();
  const pop = usePop(from, 8);
  if (frame < from || frame >= to) return null;
  const out = interpolate(frame, [to - 6, to], [1, 0], { extrapolateLeft: "clamp", extrapolateRight: "clamp" });
  const cx = x + w / 2, cy = y + h / 2;
  return (
    <g opacity={out} transform={`translate(${cx} ${cy}) scale(${pop}) translate(${-cx} ${-cy})`}>
      <path d={`M ${x + w * 0.25} ${y + h - 4} L ${tx} ${ty} L ${x + w * 0.42} ${y + h - 4} Z`} fill={C.cream} stroke={C.ink} strokeWidth={6} strokeLinejoin="round" />
      <rect x={x} y={y} width={w} height={h} rx={40} fill={C.cream} stroke={C.ink} strokeWidth={6} />
      <rect x={x + w * 0.25 + 4} y={y + h - 10} width={w * 0.17 - 8} height={12} fill={C.cream} />
      <text x={cx} y={cy + size * 0.35} textAnchor="middle" fontFamily={comic} fontSize={size} fill={C.ink} letterSpacing={1}>{text}</text>
    </g>
  );
};

/** Night city: sky gradient, stars, moon, skyline with flickering neon windows. */
export const NightCity: React.FC<{ tint?: string }> = ({ tint }) => {
  const frame = useCurrentFrame();
  const buildings = Array.from({ length: 16 }, (_, i) => {
    const w = 90 + random(`bw${i}`) * 110;
    const h = 260 + random(`bh${i}`) * 420;
    return { w, h };
  });
  let x = -40;
  const placed = buildings.map((b) => { const p = { ...b, x }; x += b.w + 8; return p; });
  return (
    <g>
      <defs>
        <linearGradient id="sky" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor={C.night} />
          <stop offset="0.65" stopColor={C.navy2} />
          <stop offset="1" stopColor={C.navy3} />
        </linearGradient>
        <radialGradient id="moonGlow">
          <stop offset="0" stopColor={C.amber} stopOpacity={0.45} />
          <stop offset="1" stopColor={C.amber} stopOpacity={0} />
        </radialGradient>
      </defs>
      <rect width={1920} height={1080} fill="url(#sky)" />
      {Array.from({ length: 90 }, (_, i) => (
        <circle key={i} cx={random(`sx${i}`) * 1920} cy={random(`sy${i}`) * 520} r={1 + random(`sr${i}`) * 2.2}
          fill={C.cream} opacity={0.35 + 0.5 * Math.abs(Math.sin(frame / 20 + i))} />
      ))}
      <circle cx={1640} cy={170} r={190} fill="url(#moonGlow)" />
      <circle cx={1640} cy={170} r={78} fill="#ffd57a" />
      <circle cx={1615} cy={150} r={14} fill="#f0bf55" />
      <circle cx={1665} cy={195} r={9} fill="#f0bf55" />
      {placed.map((b, i) => (
        <g key={i}>
          <rect x={b.x} y={900 - b.h} width={b.w} height={b.h} fill={i % 2 ? "#10163a" : "#0d1230"} />
          {Array.from({ length: Math.floor(b.h / 46) * Math.floor(b.w / 34) }, (_, j) => {
            const cols = Math.floor(b.w / 34);
            const cx = b.x + 12 + (j % cols) * 34;
            const cy = 900 - b.h + 18 + Math.floor(j / cols) * 46;
            const on = random(`w${i}-${j}`) > 0.62;
            if (!on) return null;
            const flick = random(`f${i}-${j}`) > 0.93 ? (Math.sin(frame / 3 + j) > 0 ? 1 : 0.3) : 1;
            return <rect key={j} x={cx} y={cy} width={16} height={22} rx={2} fill={random(`c${i}-${j}`) > 0.5 ? C.teal : C.amber} opacity={0.75 * flick} />;
          })}
        </g>
      ))}
      <rect y={900} width={1920} height={400} fill="#0a0e24" />
      <rect y={900} width={1920} height={6} fill={C.teal} opacity={0.5} />
      {tint && <rect width={1920} height={1080} fill={tint} />}
    </g>
  );
};

/** Bank front with a round vault door. `open` 0..1 swings the door. */
export const Bank: React.FC<{ x: number; open?: number; wheel?: number }> = ({ x, open = 0, wheel = 0 }) => (
  <g transform={`translate(${x} 0)`}>
    <rect x={0} y={330} width={760} height={570} fill="#1a2250" stroke={C.ink} strokeWidth={6} />
    <polygon points="-30,335 380,170 790,335" fill="#222c63" stroke={C.ink} strokeWidth={6} />
    <rect x={250} y={232} width={260} height={70} rx={10} fill={C.ink} stroke={C.amber} strokeWidth={4} />
    <text x={380} y={286} textAnchor="middle" fontFamily={comic} fontSize={60} fill={C.amber} letterSpacing={8}>BANK</text>
    {[40, 160, 560, 680].map((cx) => (
      <g key={cx}>
        <rect x={cx} y={350} width={46} height={540} fill="#2a356f" stroke={C.ink} strokeWidth={4} />
        <rect x={cx - 8} y={340} width={62} height={20} fill="#2f3b7c" stroke={C.ink} strokeWidth={4} />
      </g>
    ))}
    {/* vault opening */}
    <circle cx={380} cy={640} r={190} fill="#05060f" stroke={C.ink} strokeWidth={8} />
    {/* door swings open by squashing horizontally toward the left hinge */}
    <g transform={`translate(${190} 640) scale(${1 - open * 0.85} 1) translate(${-190} -640)`}>
      <circle cx={380} cy={640} r={180} fill="#9aa3b5" stroke={C.ink} strokeWidth={8} />
      <circle cx={380} cy={640} r={140} fill="#b7bfcf" stroke={C.ink} strokeWidth={5} />
      <g transform={`rotate(${wheel} 380 640)`}>
        {[0, 60, 120].map((a) => (
          <rect key={a} x={300} y={632} width={160} height={16} rx={8} fill="#5b6478" transform={`rotate(${a} 380 640)`} />
        ))}
        <circle cx={380} cy={640} r={30} fill="#5b6478" stroke={C.ink} strokeWidth={4} />
      </g>
    </g>
  </g>
);

/** Slow camera push-in for the whole scene. */
export const Camera: React.FC<{ children: React.ReactNode; from?: number; to?: number }> = ({ children, from = 1, to = 1.06 }) => {
  const frame = useCurrentFrame();
  const { durationInFrames } = useVideoConfig();
  const s = interpolate(frame, [0, durationInFrames], [from, to]);
  return <AbsoluteFill style={{ transform: `scale(${s})` }}>{children}</AbsoluteFill>;
};

/** Full-frame SVG. `lift` moves the whole set up so characters clear the caption bar. */
export const Stage: React.FC<{ children: React.ReactNode; lift?: number }> = ({ children, lift = 0 }) => (
  <svg viewBox="0 0 1920 1080" width="100%" height="100%" style={{ position: "absolute", inset: 0 }}>
    <g transform={`translate(0 ${-lift})`}>{children}</g>
  </svg>
);
