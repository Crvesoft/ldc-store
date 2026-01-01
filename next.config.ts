import type { NextConfig } from "next";

const allowAllHttpsImages = process.env.NODE_ENV === "development";

const nextConfig: NextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "linux.do",
      },
      {
        protocol: "https",
        hostname: "*.linux.do",
      },
      {
        protocol: "https",
        hostname: "images.unsplash.com",
      },
      {
        protocol: "https",
        hostname: "picsum.photos",
      },
      {
        protocol: "https",
        hostname: "via.placeholder.com",
      },
      ...(allowAllHttpsImages
        ? [
            {
              protocol: "https" as const,
              hostname: "**", // 仅开发环境放开，避免生产环境扩大攻击面
            },
          ]
        : []),
    ],
  },
};

export default nextConfig;
