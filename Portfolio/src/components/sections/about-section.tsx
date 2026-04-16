"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { aboutCards } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

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
    <PremiumSection
      id="about"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Profile"
          title="About me"
          subtitle="SRE foundations with a deliberate pivot into defensive security — from uptime to assurance."
        />
      }
    >
      <div className="grid items-start gap-10 lg:grid-cols-2 lg:gap-12">
        <MotionReveal>
          <GlassCard glow="green" className="p-7 sm:p-10">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-full border border-slate-200/70 bg-white/70 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.25em] text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300">
                <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-neon" />
                operator mindset
              </span>
              <span className="inline-flex items-center gap-2 rounded-full border border-slate-200/70 bg-white/70 px-3 py-1 font-mono text-[11px] uppercase tracking-[0.25em] text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300">
                <span className="h-1.5 w-1.5 rounded-full bg-neon-blue shadow-neon-blue" />
                blue team pivot
              </span>
            </div>

            <p className="mt-6 text-lg leading-relaxed text-slate-700 dark:text-slate-300">
              I&apos;m an SRE at{" "}
              <span className="font-semibold text-slate-900 dark:text-white">
                MakeMyTrip
              </span>
              , focused on monitoring, incident response, and root-cause analysis at
              scale. I&apos;m transitioning into cybersecurity with a SOC / Blue Team
              lens — bringing operator discipline to detection, containment, and
              continuous hardening.
            </p>

            <div className="mt-8 grid gap-4 sm:grid-cols-3">
              {[
                { k: "Focus", v: "Detection" },
                { k: "Strength", v: "IR + RCA" },
                { k: "Style", v: "Calm under fire" },
              ].map((s) => (
                <div key={s.k} className="rounded-2xl border border-slate-200/70 bg-white/60 p-4 dark:border-white/10 dark:bg-white/5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-slate-500">
                    {s.k}
                  </p>
                  <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">
                    {s.v}
                  </p>
                </div>
              ))}
            </div>
          </GlassCard>
        </MotionReveal>

        <div className="grid gap-6">
          {aboutCards.map((card, i) => (
            <MotionReveal key={card.title} delay={i * 0.07}>
              <motion.article
                whileHover={{ y: -4 }}
                transition={{ type: "spring", stiffness: 260, damping: 22 }}
                className="relative"
              >
                <GlassCard glow={i === 1 ? "purple" : i === 2 ? "blue" : "green"} className="p-6 sm:p-7">
                  <div className="flex items-start gap-4">
                    <div className="relative">
                      <div className="absolute -inset-2 rounded-2xl bg-neon-blue/10 blur-xl opacity-70" />
                      <div className="relative inline-flex h-12 w-12 items-center justify-center rounded-2xl border border-slate-200/80 bg-white/70 text-neon-blue dark:border-white/10 dark:bg-white/5">
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
                    </div>
                    <div>
                      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                        {card.title}
                      </h3>
                      <p className="mt-2 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                        {card.description}
                      </p>
                    </div>
                  </div>
                </GlassCard>
              </motion.article>
            </MotionReveal>
          ))}
        </div>
      </div>
    </PremiumSection>
  );
}
