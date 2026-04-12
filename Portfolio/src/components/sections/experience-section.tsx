"use client";

import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { experience } from "@/data/portfolio";

export function ExperienceSection() {
  return (
    <section
      id="experience"
      className="relative border-t border-slate-200/70 bg-slate-50 py-24 dark:border-white/5 dark:bg-cyber-bg"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Trajectory"
          title="Experience"
          subtitle="Reliability engineering with measurable security outcomes."
        />

        <div className="relative mx-auto max-w-3xl">
          <div className="absolute left-[11px] top-2 bottom-2 w-px bg-gradient-to-b from-neon-blue via-neon-purple to-transparent md:left-1/2 md:-ml-px" />

          {experience.map((job, index) => (
            <MotionReveal key={job.company} delay={index * 0.06}>
              <div
                className={`relative mb-12 grid gap-6 md:grid-cols-2 md:gap-10 ${
                  index % 2 === 0 ? "" : "md:text-right"
                }`}
              >
                <div
                  className={`md:pr-10 ${index % 2 === 0 ? "md:col-start-1" : "md:col-start-2"}`}
                >
                  <div className="flex items-start gap-4 md:block">
                    <span className="relative z-10 mt-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-neon-blue/40 bg-white shadow-neon-blue dark:bg-cyber-surface md:mx-auto md:mb-4">
                      <span className="h-2 w-2 rounded-full bg-neon-green" />
                    </span>
                    <div>
                      <p className="font-mono text-xs uppercase tracking-widest text-neon-blue">
                        {job.period}
                      </p>
                      <h3 className="mt-1 text-xl font-semibold text-slate-900 dark:text-white">
                        {job.role}
                      </h3>
                      <p className="text-sm text-slate-500 dark:text-slate-400">
                        {job.company}
                      </p>
                    </div>
                  </div>
                </div>

                <motion.ul
                  initial={{ opacity: 0, y: 10 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.45 }}
                  className={`space-y-3 text-sm leading-relaxed text-slate-600 dark:text-slate-400 ${
                    index % 2 === 0 ? "md:col-start-2 md:pl-10" : "md:col-start-1 md:pr-10 md:text-right"
                  }`}
                >
                  {job.highlights.map((h) => (
                    <li
                      key={h}
                      className="flex gap-2 md:items-start md:gap-3 md:[&:nth-child(n)]:flex-row-reverse"
                    >
                      <span className="mt-2 h-1 w-1 shrink-0 rounded-full bg-neon-purple md:mt-2" />
                      <span>{h}</span>
                    </li>
                  ))}
                </motion.ul>
              </div>
            </MotionReveal>
          ))}
        </div>
      </div>
    </section>
  );
}
