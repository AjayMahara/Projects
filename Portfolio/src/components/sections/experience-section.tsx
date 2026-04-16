"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { experience } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

export function ExperienceSection() {
  return (
    <PremiumSection
      id="experience"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Trajectory"
          title="Experience"
          subtitle="Reliability engineering with measurable security outcomes."
        />
      }
    >
      <div className="relative mx-auto max-w-4xl">
        <div className="pointer-events-none absolute left-3 top-0 bottom-0 w-px bg-gradient-to-b from-neon-blue via-neon-purple to-transparent md:left-1/2 md:-ml-px" />

        {experience.map((job, index) => (
          <MotionReveal key={`${job.company}-${job.role}`} delay={index * 0.06}>
            <div
              className={`relative mb-12 grid gap-6 md:grid-cols-2 md:gap-10 ${
                index % 2 === 0 ? "" : "md:text-right"
              }`}
            >
              <div
                className={`relative ${index % 2 === 0 ? "md:col-start-1 md:pr-10" : "md:col-start-2 md:pl-10"}`}
              >
                <div
                  className={`absolute left-0 top-2 -translate-x-2 md:left-1/2 md:-translate-x-1/2 ${
                    index % 2 === 0 ? "" : ""
                  }`}
                >
                  <div className="relative">
                    <div className="absolute -inset-3 rounded-full bg-neon-blue/20 blur-xl" />
                    <div className="relative flex h-7 w-7 items-center justify-center rounded-full border border-neon-blue/40 bg-white/80 shadow-neon-blue dark:bg-cyber-surface">
                      <div className="h-2 w-2 rounded-full bg-neon-green shadow-neon" />
                    </div>
                  </div>
                </div>

                <GlassCard glow="blue" className="ml-6 md:ml-0">
                  <p className="font-mono text-xs uppercase tracking-widest text-neon-blue">
                    {job.period}
                  </p>
                  <h3 className="mt-2 text-xl font-semibold text-slate-900 dark:text-white">
                    {job.role}
                  </h3>
                  <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                    {job.company}
                  </p>
                  <p className="mt-4 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                    Hover to expand highlights.
                  </p>
                </GlassCard>
              </div>

              <motion.div
                initial={false}
                className={`ml-6 md:ml-0 ${
                  index % 2 === 0 ? "md:col-start-2 md:pl-10" : "md:col-start-1 md:pr-10"
                }`}
              >
                <motion.ul
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.45 }}
                  className={`group glass overflow-hidden rounded-2xl p-6 text-sm leading-relaxed text-slate-600 dark:text-slate-400`}
                >
                  {job.highlights.map((h, hi) => (
                    <motion.li
                      key={h}
                      initial={{ opacity: 0, x: index % 2 === 0 ? 8 : -8 }}
                      whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }}
                      transition={{ delay: 0.06 * hi, duration: 0.4 }}
                      className={`flex gap-3 ${index % 2 === 0 ? "" : "md:flex-row-reverse md:text-right"}`}
                    >
                      <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-neon-purple" />
                      <span>{h}</span>
                    </motion.li>
                  ))}
                  <div className="mt-5 h-px w-full bg-gradient-to-r from-transparent via-white/10 to-transparent" />
                  <div className="mt-4 flex flex-wrap gap-2">
                    {["SLOs", "On-call", "RCA", "Hardening"].map((tag) => (
                      <span
                        key={tag}
                        className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-mono text-[11px] text-slate-200/80"
                      >
                        {tag}
                      </span>
                    ))}
                  </div>
                </motion.ul>
              </motion.div>
            </div>
          </MotionReveal>
        ))}
      </div>
    </PremiumSection>
  );
}
