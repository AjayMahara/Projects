import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#05060a",
          surface: "#0c0f18",
          border: "rgba(56, 189, 248, 0.12)",
        },
        neon: {
          green: "#22f59b",
          blue: "#38bdf8",
          purple: "#a78bfa",
          pink: "#f472b6",
        },
      },
      fontFamily: {
        sans: ["var(--font-geist-sans)", "system-ui", "sans-serif"],
        mono: ["var(--font-geist-mono)", "ui-monospace", "monospace"],
      },
      backgroundImage: {
        "grid-glow":
          "radial-gradient(ellipse 80% 50% at 50% -20%, rgba(56,189,248,0.15), transparent)",
        "mesh-gradient":
          "radial-gradient(at 40% 20%, rgba(34,245,155,0.08) 0px, transparent 50%), radial-gradient(at 80% 0%, rgba(167,139,250,0.1) 0px, transparent 50%), radial-gradient(at 0% 50%, rgba(56,189,248,0.08) 0px, transparent 50%)",
      },
      boxShadow: {
        neon: "0 0 20px rgba(34,245,155,0.25), 0 0 40px rgba(56,189,248,0.1)",
        "neon-blue": "0 0 24px rgba(56,189,248,0.35)",
        glass: "inset 0 1px 0 0 rgba(255,255,255,0.06)",
      },
      animation: {
        "pulse-slow": "pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        shimmer: "shimmer 2.5s linear infinite",
      },
      keyframes: {
        shimmer: {
          "0%": { backgroundPosition: "200% 0" },
          "100%": { backgroundPosition: "-200% 0" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
