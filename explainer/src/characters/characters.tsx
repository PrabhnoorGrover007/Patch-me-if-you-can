import React from "react";
import { C, comic } from "../theme";

type Place = { x: number; y: number; scale?: number; facing?: 1 | -1 };
const place = ({ x, y, scale = 1, facing = 1 }: Place) => `translate(${x} ${y}) scale(${scale * facing} ${scale})`;

/* ------------------------------------------------------------------ */
/* Officer CVSS: sleepy guard who only reads severity badges          */
/* ------------------------------------------------------------------ */
export const OfficerCVSS: React.FC<Place & { uid: string; stamp?: number; droop?: number; bob?: number }> = ({ uid, stamp = 0, droop = 0.55, bob = 0, ...p }) => {
  const lid = -401 + droop * 44;
  return (
    <g transform={place(p)}>
      <g transform={`translate(0 ${bob})`}>
        <defs>
          <clipPath id={`eyeL-${uid}`}><ellipse cx={-28} cy={-375} rx={22} ry={26} /></clipPath>
          <clipPath id={`eyeR-${uid}`}><ellipse cx={28} cy={-375} rx={22} ry={26} /></clipPath>
        </defs>
        {/* legs + shoes */}
        <rect x={-52} y={-112} width={38} height={104} fill="#1b2b7a" stroke={C.ink} strokeWidth={5} />
        <rect x={14} y={-112} width={38} height={104} fill="#1b2b7a" stroke={C.ink} strokeWidth={5} />
        <ellipse cx={-36} cy={-4} rx={34} ry={14} fill={C.ink} />
        <ellipse cx={36} cy={-4} rx={34} ry={14} fill={C.ink} />
        {/* clipboard arm */}
        <rect x={-150} y={-270} width={96} height={128} rx={8} fill="#8a5a2b" stroke={C.ink} strokeWidth={5} />
        <rect x={-140} y={-252} width={76} height={100} fill={C.cream} />
        {[0, 1, 2, 3].map((i) => <rect key={i} x={-132} y={-238 + i * 22} width={58} height={6} fill={i === 0 ? C.red : "#9aa"} />)}
        <rect x={-118} y={-278} width={34} height={14} rx={4} fill="#c0c6d0" stroke={C.ink} strokeWidth={3} />
        {/* body */}
        <rect x={-88} y={-305} width={176} height={205} rx={46} fill={C.guard} stroke={C.ink} strokeWidth={6} />
        <rect x={-88} y={-128} width={176} height={20} fill={C.ink} />
        <rect x={-14} y={-131} width={28} height={26} rx={4} fill={C.amber} stroke={C.ink} strokeWidth={3} />
        <polygon points="-42,-258 -35,-242 -18,-240 -31,-229 -27,-212 -42,-221 -57,-212 -53,-229 -66,-240 -49,-242" fill={C.amber} stroke={C.ink} strokeWidth={3} />
        {/* stamping arm (rotates around the shoulder) */}
        <g transform={`rotate(${-20 - stamp * 70} 70 -272)`}>
          <rect x={56} y={-276} width={36} height={128} rx={18} fill={C.guard} stroke={C.ink} strokeWidth={5} />
          <rect x={60} y={-150} width={28} height={36} rx={6} fill="#6b3f1f" stroke={C.ink} strokeWidth={4} />
          <rect x={44} y={-118} width={60} height={22} rx={4} fill={C.red} stroke={C.ink} strokeWidth={4} />
        </g>
        {/* head */}
        <circle cx={0} cy={-372} r={76} fill={C.skin} stroke={C.ink} strokeWidth={6} />
        <ellipse cx={-28} cy={-375} rx={22} ry={26} fill="#fff" stroke={C.ink} strokeWidth={4} />
        <ellipse cx={28} cy={-375} rx={22} ry={26} fill="#fff" stroke={C.ink} strokeWidth={4} />
        <circle cx={-26} cy={-366} r={9} fill={C.ink} />
        <circle cx={30} cy={-366} r={9} fill={C.ink} />
        {/* heavy eyelids */}
        <rect x={-52} y={-402} width={48} height={lid + 402} fill={C.skin} clipPath={`url(#eyeL-${uid})`} />
        <rect x={4} y={-402} width={48} height={lid + 402} fill={C.skin} clipPath={`url(#eyeR-${uid})`} />
        <line x1={-50} x2={-6} y1={lid} y2={lid} stroke={C.ink} strokeWidth={4} />
        <line x1={6} x2={50} y1={lid} y2={lid} stroke={C.ink} strokeWidth={4} />
        <ellipse cx={0} cy={-345} rx={10} ry={8} fill="#e0a26b" />
        <path d="M -18 -318 Q 0 -310 18 -318" stroke={C.ink} strokeWidth={5} fill="none" strokeLinecap="round" />
        {/* cap */}
        <path d="M -78 -420 Q -80 -478 0 -484 Q 80 -478 78 -420 Z" fill="#17246b" stroke={C.ink} strokeWidth={6} />
        <path d="M -92 -420 Q 0 -400 104 -422 Q 110 -408 96 -404 Q 0 -388 -92 -406 Z" fill={C.ink} />
        <circle cx={0} cy={-448} r={16} fill={C.amber} stroke={C.ink} strokeWidth={3} />
      </g>
    </g>
  );
};

/* ------------------------------------------------------------------ */
/* A bug (Vinny the VPN Bug, or one of the gang)                      */
/* ------------------------------------------------------------------ */
export const Bug: React.FC<Place & {
  uid: string; color?: string; walk?: number; badge?: string; badgeColor?: string;
  moustache?: boolean; moustacheDrop?: number; bag?: boolean; cuffs?: boolean; mask?: boolean; antenna?: boolean; blink?: number;
}> = ({ uid, color = C.vinny, walk = 0, badge, badgeColor = C.amber, moustache = false, moustacheDrop = 0, bag = false, cuffs = false, mask = true, antenna = false, blink = 0, ...p }) => (
  <g transform={place(p)}>
    <defs>
      <clipPath id={`body-${uid}`}><ellipse cx={0} cy={-112} rx={96} ry={80} /></clipPath>
    </defs>
    {/* legs */}
    {[-58, -10, 38].map((lx, i) => {
      const swing = Math.sin(walk + i * 2.1) * 20;
      const lift = Math.max(0, Math.cos(walk + i * 2.1)) * 10;
      return (
        <g key={i}>
          <line x1={lx} y1={-50} x2={lx + swing} y2={-4 - lift} stroke={C.ink} strokeWidth={10} strokeLinecap="round" />
          <ellipse cx={lx + swing} cy={-4 - lift} rx={14} ry={8} fill={C.ink} />
        </g>
      );
    })}
    {bag && (
      <g>
        <path d="M -150 -150 Q -175 -60 -110 -55 Q -40 -55 -62 -150 Q -100 -175 -150 -150 Z" fill="#a8743f" stroke={C.ink} strokeWidth={6} />
        <path d="M -128 -160 L -88 -160 L -95 -178 L -120 -178 Z" fill="#8a5a2b" stroke={C.ink} strokeWidth={5} />
        <text x={-106} y={-82} textAnchor="middle" fontFamily={comic} fontSize={58} fill={C.amber} stroke={C.ink} strokeWidth={2}
          transform={`translate(-106 0) scale(${p.facing ?? 1} 1) translate(106 0)`}>$</text>
      </g>
    )}
    {/* striped burglar body */}
    <ellipse cx={0} cy={-112} rx={96} ry={80} fill={color} stroke={C.ink} strokeWidth={6} />
    <g clipPath={`url(#body-${uid})`} opacity={0.85}>
      {[-150, -120, -90].map((sy) => <rect key={sy} x={-100} y={sy} width={200} height={14} fill={C.ink} opacity={0.75} />)}
    </g>
    <ellipse cx={0} cy={-112} rx={96} ry={80} fill="none" stroke={C.ink} strokeWidth={6} />
    {badge && (
      <g>
        <circle cx={-22} cy={-112} r={58} fill={badgeColor} stroke={C.ink} strokeWidth={5} />
        <text x={-22} y={-101} textAnchor="middle" fontFamily={comic} fontSize={badge.length > 6 ? 26 : 32} fill={C.ink}
          transform={`translate(-22 0) scale(${p.facing ?? 1} 1) translate(22 0)`}>{badge}</text>
      </g>
    )}
    {cuffs && (
      <g>
        <circle cx={48} cy={-70} r={16} fill="none" stroke="#c9ced8" strokeWidth={8} />
        <circle cx={82} cy={-70} r={16} fill="none" stroke="#c9ced8" strokeWidth={8} />
        <line x1={62} y1={-70} x2={68} y2={-70} stroke="#c9ced8" strokeWidth={6} />
      </g>
    )}
    {/* head */}
    {antenna && (
      <g>
        <line x1={72} y1={-248} x2={58} y2={-300} stroke={C.ink} strokeWidth={6} />
        <rect x={30} y={-326} width={58} height={26} rx={6} fill={C.navy3} stroke={C.ink} strokeWidth={4} />
        <circle cx={46} cy={-313} r={5} fill={blink > 0.5 ? C.teal : "#234"} />
        <circle cx={62} cy={-313} r={5} fill={blink > 0.5 ? "#234" : C.amber} />
        <line x1={78} y1={-326} x2={86} y2={-346} stroke={C.ink} strokeWidth={4} />
      </g>
    )}
    <circle cx={74} cy={-196} r={58} fill={color} stroke={C.ink} strokeWidth={6} />
    {mask && <rect x={26} y={-228} width={104} height={40} rx={18} fill={C.ink} />}
    <circle cx={60} cy={-208} r={18} fill="#fff" stroke={C.ink} strokeWidth={3} />
    <circle cx={102} cy={-208} r={18} fill="#fff" stroke={C.ink} strokeWidth={3} />
    <circle cx={66} cy={-206} r={8} fill={C.ink} />
    <circle cx={108} cy={-206} r={8} fill={C.ink} />
    <path d="M 66 -160 Q 84 -150 100 -160" stroke={C.ink} strokeWidth={5} fill="none" strokeLinecap="round" />
    {moustache && (
      <g transform={`translate(${moustacheDrop * 30} ${moustacheDrop * 175}) rotate(${moustacheDrop * 160} 84 -176)`}>
        <path d="M 46 -172 Q 62 -196 84 -180 Q 106 -196 122 -172 Q 104 -164 84 -172 Q 64 -164 46 -172 Z" fill="#3b2412" stroke={C.ink} strokeWidth={3} />
      </g>
    )}
  </g>
);

/* ------------------------------------------------------------------ */
/* Agent Granite: rock-solid detective                                */
/* ------------------------------------------------------------------ */
export const AgentGranite: React.FC<Place & { uid: string; tip?: number; glow?: number; magnifier?: boolean; armUp?: number }> = ({ uid, tip = 0, glow = 1, magnifier = false, armUp = 0, ...p }) => (
  <g transform={place(p)}>
    <defs>
      <filter id={`glow-${uid}`} x="-100%" y="-100%" width="300%" height="300%">
        <feGaussianBlur stdDeviation={6} result="b" />
        <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
      </filter>
    </defs>
    {/* legs */}
    <rect x={-54} y={-120} width={40} height={112} fill="#2a2d38" stroke={C.ink} strokeWidth={5} />
    <rect x={14} y={-120} width={40} height={112} fill="#2a2d38" stroke={C.ink} strokeWidth={5} />
    <ellipse cx={-38} cy={-4} rx={36} ry={14} fill={C.ink} />
    <ellipse cx={38} cy={-4} rx={36} ry={14} fill={C.ink} />
    {/* trench coat */}
    <path d="M -100 -350 L 100 -350 L 140 -95 L -140 -95 Z" fill={C.coat} stroke={C.ink} strokeWidth={6} strokeLinejoin="round" />
    <path d="M -60 -350 L 0 -250 L -30 -350 Z" fill={C.coatDark} stroke={C.ink} strokeWidth={4} />
    <path d="M 60 -350 L 0 -250 L 30 -350 Z" fill={C.coatDark} stroke={C.ink} strokeWidth={4} />
    <line x1={0} y1={-250} x2={0} y2={-95} stroke={C.ink} strokeWidth={4} />
    <rect x={-122} y={-200} width={244} height={22} fill={C.coatDark} stroke={C.ink} strokeWidth={4} />
    <rect x={-16} y={-204} width={32} height={30} rx={4} fill="none" stroke={C.amber} strokeWidth={5} />
    {[-230, -150].map((by) => <circle key={by} cx={-26} cy={by} r={7} fill={C.ink} />)}
    {/* left sleeve */}
    <path d="M -100 -345 L -150 -180 L -112 -170 L -78 -300 Z" fill={C.coat} stroke={C.ink} strokeWidth={5} />
    <circle cx={-132} cy={-170} r={20} fill={C.rock} stroke={C.ink} strokeWidth={4} />
    {/* right sleeve (can raise to tip hat / hold magnifier) */}
    <g transform={`rotate(${-armUp * 140} 92 -330)`}>
      <path d="M 100 -345 L 150 -180 L 112 -170 L 78 -300 Z" fill={C.coat} stroke={C.ink} strokeWidth={5} />
      <circle cx={132} cy={-170} r={20} fill={C.rock} stroke={C.ink} strokeWidth={4} />
      {magnifier && (
        <g>
          <line x1={140} y1={-160} x2={170} y2={-110} stroke="#6b3f1f" strokeWidth={12} strokeLinecap="round" />
          <circle cx={190} cy={-80} r={40} fill="rgba(45,226,230,0.25)" stroke={C.ink} strokeWidth={8} />
        </g>
      )}
    </g>
    {/* rock head */}
    <polygon points="-92,-372 -100,-430 -70,-490 -10,-512 58,-500 98,-452 96,-386 60,-350 -50,-348" fill={C.rock} stroke={C.ink} strokeWidth={6} strokeLinejoin="round" />
    <polyline points="-70,-490 -40,-450 10,-470 58,-500" fill="none" stroke={C.rockDark} strokeWidth={4} />
    <polyline points="-100,-430 -55,-410" fill="none" stroke={C.rockDark} strokeWidth={4} />
    {[[-60, -380], [70, -400], [20, -365], [-20, -470], [75, -460]].map(([sx, sy], i) => <circle key={i} cx={sx} cy={sy} r={5} fill={C.rockDark} />)}
    {/* glowing eyes */}
    <g filter={`url(#glow-${uid})`} opacity={0.4 + 0.6 * glow}>
      <ellipse cx={-32} cy={-418} rx={20} ry={13} fill={C.teal} />
      <ellipse cx={34} cy={-418} rx={20} ry={13} fill={C.teal} />
    </g>
    <path d="M -50 -440 L -12 -432" stroke={C.ink} strokeWidth={7} strokeLinecap="round" />
    <path d="M 52 -440 L 14 -432" stroke={C.ink} strokeWidth={7} strokeLinecap="round" />
    <path d="M -20 -378 L 24 -380" stroke={C.ink} strokeWidth={6} strokeLinecap="round" />
    {/* fedora (tips up and back) */}
    <g transform={`translate(0 ${-tip * 40}) rotate(${-tip * 18} -40 -470)`}>
      <ellipse cx={0} cy={-470} rx={140} ry={24} fill="#23232d" stroke={C.ink} strokeWidth={6} />
      <path d="M -82 -470 Q -88 -560 -30 -566 Q 0 -548 30 -566 Q 88 -560 82 -470 Z" fill="#2c2c38" stroke={C.ink} strokeWidth={6} />
      <rect x={-84} y={-500} width={168} height={22} fill={C.amber} stroke={C.ink} strokeWidth={4} />
    </g>
  </g>
);
