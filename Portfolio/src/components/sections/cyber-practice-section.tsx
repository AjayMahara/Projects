"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { cyberStats } from "@/data/portfolio";
import { PremiumSection } from "@/components/ui/premium-section";
import { GlassCard } from "@/components/ui/glass-card";

export function CyberPracticeSection() {
  return (
    <PremiumSection
      id="practice"
      className="border-t border-slate-200/70 dark:border-white/5"
      header={
        <SectionHeader
          eyebrow="Hands-on"
          title="Cybersecurity practice"
          subtitle="Deliberate reps in realistic environments — from enumeration to defensive fundamentals."
        />
      }
    >
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

          <MotionReveal className="mt-8">
            <GlassCard glow="green" className="p-6 sm:p-8">
              <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-slate-500">
                platforms
              </p>
              <div className="mt-4 flex flex-wrap gap-3">
                <PlatformBadge name="TryHackMe" tone="green" />
                <PlatformBadge name="HackTheBox" tone="blue" />
                <PlatformBadge name="Blue Team" tone="purple" />
              </div>
              <p className="mt-5 text-sm leading-relaxed text-slate-600 dark:text-slate-400">
                I keep practice intentional: enumerate, verify, document, then translate learnings into defensive controls.
              </p>
            </GlassCard>
          </MotionReveal>
        </MotionReveal>

        <MotionReveal delay={0.08}>
          <motion.div
            whileHover={{ scale: 1.01 }}
            transition={{ type: "spring", stiffness: 260, damping: 24 }}
            className="glass overflow-hidden rounded-2xl border border-slate-200/60 dark:border-white/10"
          >
            <div className="flex items-center justify-between border-b border-slate-200/60 bg-slate-900 px-4 py-2 font-mono text-[11px] text-slate-400 dark:border-white/10 dark:bg-black/40">
              <span>terminal — secure-shell</span>
              <span className="flex items-center gap-2">
                <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] uppercase tracking-widest text-slate-300">
                  scanning
                </span>
                <span className="flex gap-1">
                  <span className="h-2 w-2 rounded-full bg-red-400/80" />
                  <span className="h-2 w-2 rounded-full bg-amber-400/80" />
                  <span className="h-2 w-2 rounded-full bg-emerald-400/80" />
                </span>
              </span>
            </div>
            <div className="bg-slate-950/95 p-4 font-mono text-xs leading-relaxed sm:text-sm">
              <TypingTerminal lines={cyberStats.terminalLines} />
              <motion.p
                initial={{ opacity: 0 }}
                whileInView={{ opacity: 1 }}
                viewport={{ once: true }}
                transition={{ delay: 0.7 }}
                className="mt-3 text-neon-green"
              >
                <span className="text-neon-blue">system</span>
                <span className="text-slate-500">:</span>{" "}
                <span className="text-neon-green">ACCESS GRANTED</span>
              </motion.p>
            </div>
          </motion.div>
        </MotionReveal>
      </div>
    </PremiumSection>
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

function PlatformBadge({
  name,
  tone,
}: {
  name: string;
  tone: "blue" | "purple" | "green";
}) {
  const toneClass =
    tone === "green"
      ? "from-neon-green/25 to-neon-blue/10"
      : tone === "purple"
        ? "from-neon-purple/25 to-neon-blue/10"
        : "from-neon-blue/25 to-neon-purple/10";

  return (
    <motion.div
      whileHover={{ y: -3, scale: 1.02 }}
      transition={{ type: "spring", stiffness: 280, damping: 22 }}
      className="group relative overflow-hidden rounded-2xl border border-white/10 bg-white/5 px-4 py-3"
    >
      <div
        className={`pointer-events-none absolute inset-0 bg-gradient-to-br ${toneClass} opacity-0 transition group-hover:opacity-100`}
      />
      <div className="relative flex items-center gap-3">
        <span className="h-2 w-2 rounded-full bg-neon-green shadow-neon" />
        <span className="text-sm font-semibold text-slate-100">{name}</span>
      </div>
    </motion.div>
  );
}

function TypingTerminal({ lines }: { lines: readonly string[] }) {
  const cleaned = Array.from(lines)
    .map((l) => l.trim())
    .filter(Boolean);
  return (
    <div className="space-y-2">
      {cleaned.map((line, i) => (
        <motion.p
          key={`${line}-${i}`}
          initial={{ opacity: 0, x: -8 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          transition={{ delay: 0.08 * i, duration: 0.45 }}
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
  );
}
