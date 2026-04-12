"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { projects } from "@/data/portfolio";

export function ProjectsSection() {
  return (
    <section
      id="projects"
      className="relative border-t border-slate-200/70 bg-white py-24 dark:border-white/5 dark:bg-cyber-surface/25"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Build log"
          title="Projects"
          subtitle="Security-minded builds that pair research rigor with pragmatic engineering."
        />

        <div className="grid gap-8 md:grid-cols-2">
          {projects.map((p, i) => (
            <MotionReveal key={p.title} delay={i * 0.08}>
              <motion.article
                whileHover={{ y: -6 }}
                transition={{ type: "spring", stiffness: 260, damping: 22 }}
                className="group glass relative h-full overflow-hidden rounded-2xl p-6 sm:p-8"
              >
                <div className="pointer-events-none absolute -right-16 top-0 h-40 w-40 rounded-full bg-neon-purple/15 blur-3xl transition duration-500 group-hover:bg-neon-blue/20" />
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
                <div className="mt-8 flex items-center justify-between">
                  <a
                    href={p.github}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-2 text-sm font-medium text-neon-blue transition hover:text-neon-green"
                  >
                    View on GitHub
                    <span aria-hidden>↗</span>
                  </a>
                  <span className="font-mono text-[10px] uppercase tracking-[0.25em] text-slate-400">
                    repo
                  </span>
                </div>
              </motion.article>
            </MotionReveal>
          ))}
        </div>
      </div>
    </section>
  );
}
