import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // The CVE dataset is a 700 KB JSON module; keep it server-side and let each
  // page hand the client only the records it renders.
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
};

export default nextConfig;
