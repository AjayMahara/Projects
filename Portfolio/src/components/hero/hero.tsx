"use client";

import dynamic from "next/dynamic";
import { motion } from "framer-motion";
import { useTypingRoles } from "@/hooks/use-typing-roles";
import { SITE } from "@/data/portfolio";

const HeroScene = dynamic(
  () => import("./hero-scene").then((m) => m.HeroScene),
  { ssr: false, loading: () => <HeroCanvasFallback /> },
);

function HeroCanvasFallback() {
  return (
    <div className="absolute inset-0 animate-pulse bg-gradient-to-br from-slate-900 via-cyber-bg to-slate-950" />
  );
}

const floatIcons = [
  { label: "lock", x: "12%", y: "22%", delay: 0 },
  { label: "shield", x: "82%", y: "28%", delay: 0.2 },
  { label: "cloud", x: "18%", y: "72%", delay: 0.4 },
  { label: "terminal", x: "78%", y: "68%", delay: 0.15 },
] as const;

export function Hero() {
  const typed = useTypingRoles(SITE.roles, 68, 1500);

  return (
    <section
      id="top"
      className="relative isolate min-h-[100svh] overflow-hidden bg-slate-50 dark:bg-cyber-bg"
    >
      <HeroScene />

      <div className="pointer-events-none absolute inset-0 bg-mesh-gradient dark:bg-mesh-gradient" />

      {floatIcons.map((icon) => (
        <motion.div
          key={icon.label}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 0.35, y: [0, -6, 0] }}
          transition={{
            opacity: { duration: 0.8, delay: icon.delay },
            y: { duration: 5 + icon.delay * 3, repeat: Infinity, ease: "easeInOut" },
          }}
          className="pointer-events-none absolute hidden text-neon-purple/70 lg:block"
          style={{ left: icon.x, top: icon.y }}
        >
          <span className="font-mono text-[10px] uppercase tracking-widest">
            [{icon.label}]
          </span>
        </motion.div>
      ))}

      <div className="relative z-10 mx-auto flex min-h-[100svh] max-w-6xl flex-col justify-center px-4 pb-24 pt-28 sm:px-6 lg:pb-32 lg:pt-32">
        <div className="max-w-2xl">
          <motion.p
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="mb-4 inline-flex items-center gap-2 rounded-full border border-slate-200/80 bg-white/60 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.2em] text-slate-600 shadow-sm backdrop-blur-md dark:border-white/10 dark:bg-white/5 dark:text-slate-300"
          >
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-neon-green shadow-neon" />
            online
          </motion.p>

          <motion.h1
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.05 }}
            className="text-4xl font-semibold tracking-tight text-slate-900 dark:text-white sm:text-5xl lg:text-6xl"
          >
            {SITE.name}
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.12 }}
            className="mt-3 text-lg text-slate-600 dark:text-slate-300 sm:text-xl"
          >
            {SITE.title}
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.18 }}
            className="mt-6 flex min-h-[2.5rem] items-center font-mono text-sm text-neon-blue sm:text-base"
          >
            <span className="mr-2 text-slate-500 dark:text-slate-500">$ roles</span>
            <span className="text-gradient font-semibold">
              {typed}
              <span className="ml-0.5 inline-block h-5 w-0.5 animate-pulse bg-neon-blue align-middle" />
            </span>
          </motion.div>

          <motion.p
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.22 }}
            className="mt-6 max-w-xl text-pretty text-base leading-relaxed text-slate-600 dark:text-slate-400"
          >
            {SITE.tagline}
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, delay: 0.28 }}
            className="mt-10 flex flex-wrap items-center gap-4"
          >
            <a
              href="#projects"
              className="pointer-events-auto inline-flex items-center justify-center rounded-full bg-gradient-to-r from-neon-green to-neon-blue px-7 py-3 text-sm font-semibold text-cyber-bg shadow-neon transition hover:brightness-110"
            >
              View Projects
            </a>
            <a
              href="#contact"
              className="pointer-events-auto glass inline-flex items-center justify-center rounded-full px-7 py-3 text-sm font-medium text-slate-800 transition hover:border-neon-blue/40 hover:shadow-neon-blue dark:text-slate-100"
            >
              Contact Me
            </a>
          </motion.div>
        </div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.9, duration: 0.6 }}
          className="pointer-events-none absolute bottom-8 left-1/2 hidden -translate-x-1/2 md:block"
        >
          <div className="flex flex-col items-center gap-2 text-[10px] font-mono uppercase tracking-[0.35em] text-slate-500">
            <span>scroll</span>
            <span className="h-8 w-px bg-gradient-to-b from-neon-blue to-transparent" />
          </div>
        </motion.div>
      </div>
    </section>
  );
}
