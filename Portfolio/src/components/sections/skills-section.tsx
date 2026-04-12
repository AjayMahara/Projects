"use client";

import { motion, useInView } from "framer-motion";
import { useRef } from "react";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { skills } from "@/data/portfolio";

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

  return (
    <section
      id="skills"
      className="relative border-t border-slate-200/70 bg-white py-24 dark:border-white/5 dark:bg-cyber-surface/30"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Stack"
          title="Skills"
          subtitle="Operator-grade tooling across build, observe, respond, and secure."
        />

        <div className="grid gap-8 lg:grid-cols-2">
          {categories.map(([title, items], ci) => (
            <MotionReveal key={title} delay={ci * 0.05}>
              <motion.div
                whileHover={{ y: -3 }}
                transition={{ type: "spring", stiffness: 280, damping: 24 }}
                className="glass h-full rounded-2xl p-6 sm:p-8"
              >
                <div className="mb-6 flex flex-wrap items-center gap-2">
                  <h3 className="text-lg font-semibold text-slate-900 dark:text-white">
                    {title}
                  </h3>
                  <span className="rounded-full border border-slate-200/80 bg-white/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-widest text-slate-500 dark:border-white/10 dark:bg-white/5 dark:text-slate-400">
                    proficiency
                  </span>
                </div>
                <div className="space-y-5">
                  {items.map((s, i) => (
                    <SkillBar
                      key={s.name}
                      name={s.name}
                      level={s.level}
                      delay={0.06 * i + ci * 0.04}
                    />
                  ))}
                </div>
              </motion.div>
            </MotionReveal>
          ))}
        </div>

        <MotionReveal className="mt-10">
          <div className="flex flex-wrap justify-center gap-2">
            {[
              "Python",
              "Bash",
              "Splunk",
              "Grafana",
              "Zabbix",
              "AWS",
              "GCP",
              "Azure",
              "THM",
              "HTB",
            ].map((tag) => (
              <span
                key={tag}
                className="rounded-full border border-slate-200/80 bg-gradient-to-r from-white to-slate-50 px-3 py-1 text-xs font-medium text-slate-700 shadow-sm dark:border-white/10 dark:from-white/5 dark:to-white/[0.02] dark:text-slate-200"
              >
                {tag}
              </span>
            ))}
          </div>
        </MotionReveal>
      </div>
    </section>
  );
}
