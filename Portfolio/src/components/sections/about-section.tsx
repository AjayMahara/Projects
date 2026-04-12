"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { aboutCards } from "@/data/portfolio";

function CardIcon({ name }: { name: (typeof aboutCards)[number]["icon"] }) {
  const common = {
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    strokeWidth: 1.5,
  };
  if (name === "chart") {
    return <path {...common} d="M4 19V5M8 19V9m4 10V7m4 12v-6" />;
  }
  if (name === "shield") {
    return <path {...common} d="M12 3l7 4v5c0 5-3 9-7 10-4-1-7-5-7-10V7l7-4z" />;
  }
  return <path {...common} d="M7 11V8a5 5 0 0110 0v3M6 11h12v9H6V11z" />;
}

export function AboutSection() {
  return (
    <section
      id="about"
      className="relative border-t border-slate-200/70 bg-white py-24 dark:border-white/5 dark:bg-cyber-surface/40"
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-40 bg-grid-glow opacity-60 dark:opacity-100" />
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Profile"
          title="About me"
          subtitle="SRE foundations with a deliberate pivot into defensive security — from uptime to assurance."
        />

        <MotionReveal className="mx-auto max-w-3xl text-center">
          <p className="text-lg leading-relaxed text-slate-600 dark:text-slate-400">
            I&apos;m an SRE at{" "}
            <span className="font-semibold text-slate-900 dark:text-white">
              MakeMyTrip
            </span>
            , focused on monitoring, incident response, and root-cause analysis at
            scale. I&apos;m transitioning into cybersecurity with a SOC / Blue Team
            lens — bringing operator discipline to detection, containment, and
            continuous hardening.
          </p>
        </MotionReveal>

        <div className="mt-14 grid gap-6 md:grid-cols-3">
          {aboutCards.map((card, i) => (
            <MotionReveal key={card.title} delay={i * 0.08}>
              <motion.article
                whileHover={{ y: -4, scale: 1.01 }}
                transition={{ type: "spring", stiffness: 260, damping: 22 }}
                className="glass group relative h-full overflow-hidden rounded-2xl p-6 shadow-sm"
              >
                <div className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full bg-neon-blue/10 blur-2xl transition group-hover:bg-neon-green/15" />
                <div className="mb-4 inline-flex h-11 w-11 items-center justify-center rounded-xl border border-slate-200/80 bg-white/70 text-neon-blue dark:border-white/10 dark:bg-white/5">
                  <svg
                    className="h-5 w-5"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    aria-hidden
                  >
                    <CardIcon name={card.icon} />
                  </svg>
                </div>
                <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                  {card.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                  {card.description}
                </p>
              </motion.article>
            </MotionReveal>
          ))}
        </div>
      </div>
    </section>
  );
}
