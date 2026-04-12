"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { certifications } from "@/data/portfolio";

export function CertificationsSection() {
  return (
    <section
      id="certs"
      className="relative border-t border-slate-200/70 bg-slate-50 py-24 dark:border-white/5 dark:bg-cyber-bg"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Credentials"
          title="Certifications"
          subtitle="Foundational cloud fluency paired with offensive awareness — applied defensively."
        />

        <div
          className="mx-auto grid max-w-4xl gap-8 md:grid-cols-2"
          style={{ perspective: "1200px" }}
        >
          {certifications.map((c, i) => (
            <MotionReveal key={c.name} delay={i * 0.08}>
              <motion.div
                whileHover={{ y: -5, rotateX: 4, rotateY: -4 }}
                transition={{ type: "spring", stiffness: 220, damping: 18 }}
                style={{ transformStyle: "preserve-3d" }}
                className="group relative overflow-hidden rounded-2xl border border-slate-200/70 bg-gradient-to-br from-white to-slate-50 p-[1px] shadow-sm dark:border-white/10 dark:from-white/10 dark:to-white/[0.02]"
              >
                <div className="relative rounded-[15px] bg-white/90 p-8 dark:bg-cyber-surface/90">
                  <div className="absolute right-6 top-6 h-16 w-16 rounded-full bg-neon-blue/10 blur-2xl transition group-hover:bg-neon-green/20" />
                  <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                    {c.issuer}
                  </p>
                  <h3 className="mt-3 text-lg font-semibold text-slate-900 dark:text-white">
                    {c.name}
                  </h3>
                  <div className="mt-6 inline-flex items-center gap-2 rounded-full border border-slate-200/80 bg-slate-50 px-3 py-1 text-xs font-medium text-slate-600 dark:border-white/10 dark:bg-white/5 dark:text-slate-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-neon-green shadow-neon" />
                    {c.year}
                  </div>
                </div>
              </motion.div>
            </MotionReveal>
          ))}
        </div>
      </div>
    </section>
  );
}
