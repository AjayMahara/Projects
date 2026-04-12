"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { cyberStats } from "@/data/portfolio";

export function CyberPracticeSection() {
  return (
    <section
      id="practice"
      className="relative border-t border-slate-200/70 bg-slate-50 py-24 dark:border-white/5 dark:bg-cyber-bg"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Hands-on"
          title="Cybersecurity practice"
          subtitle="Deliberate reps in realistic environments — from enumeration to defensive fundamentals."
        />

        <div className="grid gap-8 lg:grid-cols-2">
          <MotionReveal>
            <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-1 xl:grid-cols-3">
              <StatBadge
                label="TryHackMe"
                value={cyberStats.tryhackme.rank}
                hint="Global rank"
              />
              <StatBadge
                label="Rooms"
                value={String(cyberStats.tryhackme.rooms)}
                hint="Completed"
              />
              <StatBadge
                label="Badges"
                value={String(cyberStats.tryhackme.badges)}
                hint="Earned"
              />
            </div>
            <div className="mt-4 grid gap-4 sm:grid-cols-2">
              <StatBadge
                label="HackTheBox"
                value={`${cyberStats.htb.machines} machines`}
                hint="Practice"
              />
              <StatBadge
                label="Challenges"
                value={String(cyberStats.htb.challenges)}
                hint="Completed"
              />
            </div>
          </MotionReveal>

          <MotionReveal delay={0.08}>
            <motion.div
              whileHover={{ scale: 1.01 }}
              transition={{ type: "spring", stiffness: 260, damping: 24 }}
              className="glass overflow-hidden rounded-2xl border border-slate-200/60 dark:border-white/10"
            >
              <div className="flex items-center justify-between border-b border-slate-200/60 bg-slate-900 px-4 py-2 font-mono text-[11px] text-slate-400 dark:border-white/10 dark:bg-black/40">
                <span>terminal — zsh</span>
                <span className="flex gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-400/80" />
                  <span className="h-2 w-2 rounded-full bg-amber-400/80" />
                  <span className="h-2 w-2 rounded-full bg-emerald-400/80" />
                </span>
              </div>
              <div className="space-y-2 bg-slate-950/95 p-4 font-mono text-xs leading-relaxed text-neon-green sm:text-sm">
                {cyberStats.terminalLines.map((line, i) => (
                  <motion.p
                    key={line}
                    initial={{ opacity: 0, x: -6 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.06 * i }}
                    className="text-slate-300"
                  >
                    <span className="text-neon-blue">user@lab</span>
                    <span className="text-slate-500">:</span>
                    <span className="text-neon-purple">~/practice</span>
                    <span className="text-slate-500">$ </span>
                    <span className="text-slate-100">{line}</span>
                  </motion.p>
                ))}
              </div>
            </motion.div>
          </MotionReveal>
        </div>
      </div>
    </section>
  );
}

function StatBadge({
  label,
  value,
  hint,
}: {
  label: string;
  value: string;
  hint: string;
}) {
  return (
    <motion.div
      whileHover={{ y: -3 }}
      className="group glass relative overflow-hidden rounded-2xl p-5"
    >
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-neon-blue/10 via-transparent to-neon-purple/10 opacity-0 transition group-hover:opacity-100" />
      <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-slate-500">
        {label}
      </p>
      <p className="mt-2 text-2xl font-semibold text-slate-900 dark:text-white">
        {value}
      </p>
      <p className="mt-1 text-xs text-slate-500">{hint}</p>
    </motion.div>
  );
}
