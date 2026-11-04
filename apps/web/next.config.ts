import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@vibeaudit/shared", "@vibeaudit/db"],
  // postgres opens raw sockets; load it from node_modules instead of bundling it.
  serverExternalPackages: ["postgres"],
  poweredByHeader: false,
  // Caddy compresses in front of us; Next's gzip would also buffer the SSE progress stream.
  compress: false,
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
