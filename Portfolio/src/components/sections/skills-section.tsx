"use client";

import { motion, useInView } from "framer-motion";
import { useMemo, useRef, useState } from "react";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { skills } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

function SkillBar({
  name,
  level,
  delay,
}: {
  name: string;
  level: number;
  delay: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-10%" });

  return (
    <div ref={ref} className="space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-slate-800 dark:text-slate-200">{name}</span>
        <span className="font-mono text-xs text-slate-500">{level}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded-full bg-slate-200/80 dark:bg-white/5">
        <motion.div
          initial={{ width: 0 }}
          animate={inView ? { width: `${level}%` } : { width: 0 }}
          transition={{ duration: 1.1, delay, ease: [0.22, 1, 0.36, 1] }}
          className="h-full rounded-full bg-gradient-to-r from-neon-green via-neon-blue to-neon-purple shadow-neon"
        />
      </div>
    </div>
  );
}

export function SkillsSection() {
  const categories = Object.entries(skills) as [
    keyof typeof skills,
    (typeof skills)[keyof typeof skills],
  ][];
  const [active, setActive] = useState<string>(String(categories[0]?.[0] ?? ""));
  const activeItems = useMemo(
    () => categories.find(([t]) => String(t) === active)?.[1] ?? categories[0]?.[1] ?? [],
    [active, categories],
  );

  return (
    <PremiumSection
      id="skills"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Stack"
          title="Skills"
          subtitle="Operator-grade tooling across build, observe, respond, and secure."
        />
      }
    >
      <div className="grid gap-8 lg:grid-cols-12 lg:gap-10">
        <MotionReveal className="lg:col-span-4">
          <GlassCard glow="purple" className="p-6 sm:p-8">
            <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
              categories
            </p>
            <div className="mt-4 grid gap-2">
              {categories.map(([title]) => {
                const t = String(title);
                const on = t === active;
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setActive(t)}
                    className={`group flex items-center justify-between rounded-2xl border px-4 py-3 text-left transition ${
                      on
                        ? "border-neon-blue/40 bg-white/70 shadow-neon-blue dark:bg-white/5"
                        : "border-slate-200/70 bg-white/50 hover:border-neon-purple/35 hover:bg-white/70 dark:border-white/10 dark:bg-white/[0.03] dark:hover:bg-white/[0.06]"
                    }`}
                  >
                    <span className="text-sm font-semibold text-slate-900 dark:text-white">
                      {t}
                    </span>
                    <span
                      className={`h-1.5 w-1.5 rounded-full transition ${
                        on ? "bg-neon-green shadow-neon" : "bg-slate-300 dark:bg-white/20"
                      }`}
                      aria-hidden
                    />
                  </button>
                );
              })}
            </div>
            <p className="mt-6 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
              Click a category to reveal a focused proficiency panel with animated bars.
            </p>
          </GlassCard>
        </MotionReveal>

        <MotionReveal className="lg:col-span-8" delay={0.06}>
          <GlassCard glow="blue" className="p-6 sm:p-8">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                  active
                </p>
                <h3 className="mt-2 text-xl font-semibold text-slate-900 dark:text-white">
                  {active}
                </h3>
              </div>
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-mono text-[11px] uppercase tracking-widest text-slate-500 dark:text-slate-300">
                proficiency
              </span>
            </div>

            <div className="mt-7 space-y-5">
              {activeItems.map((s, i) => (
                <SkillBar
                  key={s.name}
                  name={s.name}
                  level={s.level}
                  delay={0.05 * i}
                />
              ))}
            </div>

            <div className="mt-8 rounded-2xl border border-white/10 bg-white/5 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                quick tags
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {Array.from(new Set(categories.flatMap(([, items]) => items.map((x) => x.name))))
                  .slice(0, 14)
                  .map((tag) => (
                    <motion.span
                      key={tag}
                      whileHover={{ y: -2, scale: 1.02 }}
                      className="rounded-full border border-slate-200/70 bg-gradient-to-r from-white to-slate-50 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm dark:border-white/10 dark:from-white/5 dark:to-white/[0.02] dark:text-slate-200"
                    >
                      {tag}
                    </motion.span>
                  ))}
              </div>
            </div>
          </GlassCard>
        </MotionReveal>
      </div>
    </PremiumSection>
  );
}
