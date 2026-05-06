"use client";

import { motion } from "framer-motion";
import { useMemo, useState } from "react";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { skills } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

function SkillTile({
  name,
  index,
}: {
  name: string;
  index: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10, scale: 0.98 }}
      whileInView={{ opacity: 1, y: 0, scale: 1 }}
      viewport={{ once: true, margin: "-10% 0px" }}
      transition={{ duration: 0.45, delay: Math.min(index * 0.03, 0.36) }}
      whileHover={{ y: -4, scale: 1.02 }}
      className="group relative"
    >
      <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-neon-blue/20 via-transparent to-neon-purple/20 opacity-0 blur-xl transition duration-500 group-hover:opacity-100" />
      <div className="relative rounded-2xl border border-slate-200/70 bg-white/60 px-4 py-3 shadow-sm backdrop-blur-md transition duration-300 group-hover:border-neon-blue/40 group-hover:bg-white/70 group-hover:shadow-neon-blue dark:border-white/10 dark:bg-white/[0.04] dark:group-hover:bg-white/[0.07]">
        <div className="pointer-events-none absolute inset-0 rounded-2xl opacity-0 transition group-hover:opacity-100">
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-white/10 via-transparent to-white/5 dark:from-white/5" />
        </div>
        <div className="relative flex items-center justify-between gap-3">
          <span className="text-sm font-semibold text-slate-900 dark:text-white">
            {name}
          </span>
          <span
            className="h-1.5 w-1.5 rounded-full bg-slate-300 transition group-hover:bg-neon-green group-hover:shadow-neon dark:bg-white/15"
            aria-hidden
          />
        </div>
      </div>
    </motion.div>
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
  const allSkillNames = useMemo(
    () =>
      Array.from(
        new Set(categories.flatMap(([, items]) => items.map((x) => x.name))),
      ),
    [categories],
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

            <div className="mt-6 rounded-2xl border border-white/10 bg-white/5 p-5">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                highlight
              </p>
              <p className="mt-3 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                No proficiency scores — just the tools I&apos;m actively using and
                building with.
              </p>
            </div>
          </GlassCard>
        </MotionReveal>

        <MotionReveal className="lg:col-span-8" delay={0.06}>
          <GlassCard glow="blue" className="p-6 sm:p-8">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                  active set
                </p>
                <h3 className="mt-2 text-xl font-semibold text-slate-900 dark:text-white">
                  {active}
                </h3>
              </div>
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 font-mono text-[10px] uppercase tracking-[0.25em] text-slate-300">
                {activeItems.length} skills
              </span>
            </div>

            <div className="mt-7 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {activeItems.map((s, i) => (
                <SkillTile key={s.name} name={s.name} index={i} />
              ))}
            </div>

            <div className="mt-10">
              <div className="mb-4 flex items-center justify-between gap-3">
                <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                  full index
                </p>
                <span className="text-xs text-slate-500">
                  {allSkillNames.length} total
                </span>
              </div>
              <div className="flex flex-wrap gap-2">
                {allSkillNames.map((tag) => (
                  <motion.span
                    key={tag}
                    whileHover={{ y: -2, scale: 1.02 }}
                    transition={{ type: "spring", stiffness: 320, damping: 24 }}
                    className="rounded-full border border-slate-200/70 bg-gradient-to-r from-white to-slate-50 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm transition hover:border-neon-blue/40 hover:shadow-neon-blue dark:border-white/10 dark:from-white/5 dark:to-white/[0.02] dark:text-slate-200"
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
