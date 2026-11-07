import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@vibeaudit/shared", "@vibeaudit/db"],
  // postgres opens raw sockets; pdfkit reads its data files from disk: load both from node_modules.
  serverExternalPackages: ["postgres", "pdfkit"],
  poweredByHeader: false,
  // The PDF route reads its fonts, and in the read-only demo its screenshots, from disk: make sure
  // hosts that bundle each route (Vercel) ship them with it.
  outputFileTracingIncludes: {
    // Keys are globs (a literal "[id]" would be a character class), hence the "*".
    "/api/audits/*/report.pdf": ["./assets/fonts/*.ttf", "./public/demo/**/*.jpg"],
  },
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
