// Temporary stand-in for scenes 4-7 until they are built.
import React from "react";
import { AbsoluteFill } from "remotion";
import { NightCity, Stage } from "../components";
import { body, C, comic } from "../theme";

export const Placeholder: React.FC<{ n: number; title: string }> = ({ n, title }) => (
  <AbsoluteFill style={{ background: C.night }}>
    <Stage><NightCity tint="rgba(7,10,26,0.7)" /></Stage>
    <AbsoluteFill style={{ justifyContent: "center", alignItems: "center", textAlign: "center" }}>
      <div style={{ fontFamily: comic, fontSize: 120, color: C.amber }}>SCENE {n}</div>
      <div style={{ fontFamily: body, fontWeight: 800, fontSize: 56, color: C.cream }}>{title}</div>
      <div style={{ fontFamily: body, fontWeight: 600, fontSize: 36, color: C.teal, marginTop: 20 }}>being built next</div>
    </AbsoluteFill>
  </AbsoluteFill>
);
