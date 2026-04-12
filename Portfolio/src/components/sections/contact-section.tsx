"use client";

import { useState } from "react";
import { motion } from "framer-motion";
import { MotionReveal } from "@/components/motion-reveal";
import { SectionHeader } from "@/components/section-header";
import { SITE } from "@/data/portfolio";

export function ContactSection() {
  const [sent, setSent] = useState(false);

  return (
    <section
      id="contact"
      className="relative border-t border-slate-200/70 bg-white py-24 dark:border-white/5 dark:bg-cyber-surface/30"
    >
      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        <SectionHeader
          eyebrow="Connect"
          title="Contact"
          subtitle="Open to SOC analyst and security engineering opportunities."
        />

        <div className="grid gap-10 lg:grid-cols-2">
          <MotionReveal>
            <div className="space-y-6">
              <a
                href={`mailto:${SITE.email}`}
                className="block rounded-2xl border border-slate-200/80 bg-slate-50/80 p-5 transition hover:border-neon-blue/40 hover:shadow-neon-blue dark:border-white/10 dark:bg-white/5"
              >
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-slate-500">
                  Email
                </p>
                <p className="mt-2 text-lg font-medium text-slate-900 dark:text-white">
                  {SITE.email}
                </p>
              </a>
              <a
                href={SITE.linkedin}
                target="_blank"
                rel="noreferrer"
                className="block rounded-2xl border border-slate-200/80 bg-slate-50/80 p-5 transition hover:border-neon-purple/40 hover:shadow-[0_0_24px_rgba(167,139,250,0.25)] dark:border-white/10 dark:bg-white/5"
              >
                <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-slate-500">
                  LinkedIn
                </p>
                <p className="mt-2 text-lg font-medium text-slate-900 dark:text-white">
                  Profile ↗
                </p>
              </a>
            </div>
          </MotionReveal>

          <MotionReveal delay={0.06}>
            <form
              className="glass space-y-4 rounded-2xl p-6 sm:p-8"
              onSubmit={(e) => {
                e.preventDefault();
                const fd = new FormData(e.currentTarget);
                const name = String(fd.get("name") ?? "").trim();
                const email = String(fd.get("email") ?? "").trim();
                const message = String(fd.get("message") ?? "").trim();
                if (!name || !email || !message) return;
                const subject = encodeURIComponent(
                  `Portfolio inquiry from ${name}`,
                );
                const body = encodeURIComponent(
                  `From: ${name} <${email}>\n\n${message}`,
                );
                window.location.href = `mailto:${SITE.email}?subject=${subject}&body=${body}`;
                setSent(true);
              }}
            >
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="space-y-2 text-sm">
                  <span className="text-slate-600 dark:text-slate-400">Name</span>
                  <input
                    name="name"
                    required
                    className="w-full rounded-xl border border-slate-200/80 bg-white/80 px-3 py-2 text-slate-900 outline-none ring-neon-blue/30 transition focus:ring-2 dark:border-white/10 dark:bg-black/30 dark:text-white"
                  />
                </label>
                <label className="space-y-2 text-sm">
                  <span className="text-slate-600 dark:text-slate-400">Email</span>
                  <input
                    name="email"
                    type="email"
                    required
                    className="w-full rounded-xl border border-slate-200/80 bg-white/80 px-3 py-2 text-slate-900 outline-none ring-neon-blue/30 transition focus:ring-2 dark:border-white/10 dark:bg-black/30 dark:text-white"
                  />
                </label>
              </div>
              <label className="block space-y-2 text-sm">
                <span className="text-slate-600 dark:text-slate-400">Message</span>
                <textarea
                  name="message"
                  required
                  rows={5}
                  className="w-full resize-none rounded-xl border border-slate-200/80 bg-white/80 px-3 py-2 text-slate-900 outline-none ring-neon-blue/30 transition focus:ring-2 dark:border-white/10 dark:bg-black/30 dark:text-white"
                />
              </label>
              <motion.button
                type="submit"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
                className="w-full rounded-full bg-gradient-to-r from-neon-green to-neon-blue py-3 text-sm font-semibold text-cyber-bg shadow-neon"
              >
                Send message
              </motion.button>
              {sent ? (
                <p className="text-center text-xs text-slate-500">
                  If your mail client did not open, email me directly at{" "}
                  <span className="text-neon-blue">{SITE.email}</span>.
                </p>
              ) : null}
            </form>
          </MotionReveal>
        </div>
      </div>
    </section>
  );
}
