import type { NextConfig } from "next";

const API_TARGET = (process.env.API_BASE || "http://127.0.0.1:8000").replace(/\/$/, "");

const nextConfig: NextConfig = {
  // Browser-side tables page through FastAPI without shipping the 72,670-row
  // dataset or exposing an internal host name in client code.
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${API_TARGET}/api/:path*` }];
  },
  experimental: {
    serverActions: { bodySizeLimit: "2mb" },
  },
};

export default nextConfig;
