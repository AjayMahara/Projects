"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { certifications } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

export function CertificationsSection() {
  return (
    <PremiumSection
      id="certs"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Credentials"
          title="Certifications"
          subtitle="Foundational cloud fluency paired with offensive awareness — applied defensively."
        />
      }
    >
      <div className="mx-auto grid max-w-5xl gap-6 md:grid-cols-2">
        {certifications.map((c, i) => (
          <MotionReveal key={c.name} delay={i * 0.08}>
            <motion.div
              whileHover={{ y: -6 }}
              transition={{ type: "spring", stiffness: 230, damping: 20 }}
              className="h-full"
            >
              <GlassCard glow={i % 2 === 0 ? "green" : "purple"} className="h-full">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                      {c.issuer}
                    </p>
                    <h3 className="mt-3 text-lg font-semibold text-slate-900 dark:text-white">
                      {c.name}
                    </h3>
                  </div>
                  <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.25em] text-slate-300">
                    verified
                  </span>
                </div>

                <div className="mt-6 flex flex-wrap items-center gap-3">
                  <div className="inline-flex items-center gap-2 rounded-full border border-slate-200/70 bg-white/70 px-3 py-1 text-xs font-semibold text-slate-700 shadow-sm dark:border-white/10 dark:bg-white/5 dark:text-slate-200">
                    <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-neon" />
                    {c.year}
                  </div>
                  <motion.span
                    whileHover={{ y: -2 }}
                    className="inline-flex items-center gap-2 rounded-full border border-slate-200/70 bg-gradient-to-r from-white to-slate-50 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm dark:border-white/10 dark:from-white/5 dark:to-white/[0.02] dark:text-slate-200"
                  >
                    badge
                  </motion.span>
                </div>
              </GlassCard>
            </motion.div>
          </MotionReveal>
        ))}
      </div>
    </PremiumSection>
  );
}
