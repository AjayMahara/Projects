"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { projects } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { HoverTilt } from "@/components/ui/hover-tilt";
import { GlassCard } from "@/components/ui/glass-card";

export function ProjectsSection() {
  return (
    <PremiumSection
      id="projects"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Build log"
          title="Projects"
          subtitle="Security-minded builds that pair research rigor with pragmatic engineering."
        />
      }
    >
      <div className="grid gap-8 md:grid-cols-2">
        {projects.map((p, i) => (
          <MotionReveal key={p.title} delay={i * 0.08}>
            <HoverTilt max={12} className="h-full">
              <GlassCard glow={i % 2 === 0 ? "purple" : "blue"} className="h-full p-0">
                <div className="relative overflow-hidden rounded-2xl">
                  <div className="relative h-44 w-full border-b border-white/10 bg-gradient-to-br from-neon-blue/15 via-transparent to-neon-purple/20">
                    <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,rgba(34,245,155,0.15),transparent_35%),radial-gradient(circle_at_70%_60%,rgba(56,189,248,0.12),transparent_40%)]" />
                    <div className="absolute inset-0 opacity-40 [background-image:linear-gradient(to_right,rgba(255,255,255,0.06)_1px,transparent_1px),linear-gradient(to_bottom,rgba(255,255,255,0.06)_1px,transparent_1px)] [background-size:44px_44px]" />
                    <div className="absolute left-5 top-5 inline-flex items-center gap-2 rounded-full border border-white/10 bg-black/20 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.25em] text-slate-200 backdrop-blur-md">
                      <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-neon" />
                      preview
                    </div>
                  </div>

                  <div className="p-6 sm:p-8">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <h3 className="text-xl font-semibold text-slate-900 dark:text-white">
                          {p.title}
                        </h3>
                        <p className="mt-3 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                          {p.description}
                        </p>
                      </div>
                    </div>

                    <div className="mt-6 flex flex-wrap gap-2">
                      {p.stack.map((t) => (
                        <span
                          key={t}
                          className="rounded-full border border-slate-200/70 bg-white/70 px-2.5 py-1 font-mono text-[11px] text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300"
                        >
                          {t}
                        </span>
                      ))}
                    </div>

                    <div className="mt-8 flex flex-wrap items-center justify-between gap-3">
                      <a
                        href={p.github}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-2 text-sm font-medium text-neon-blue transition hover:text-neon-green"
                      >
                        View on GitHub
                        <span aria-hidden>↗</span>
                      </a>
                      <motion.button
                        type="button"
                        whileHover={{ y: -2 }}
                        whileTap={{ scale: 0.98 }}
                        className="rounded-full border border-slate-200/70 bg-white/70 px-4 py-2 text-xs font-semibold text-slate-800 shadow-sm transition hover:border-neon-blue/40 hover:shadow-neon-blue dark:border-white/10 dark:bg-white/5 dark:text-slate-100"
                      >
                        View details
                      </motion.button>
                    </div>
                  </div>
                </div>
              </GlassCard>
            </HoverTilt>
          </MotionReveal>
        ))}
      </div>
    </PremiumSection>
  );
}
