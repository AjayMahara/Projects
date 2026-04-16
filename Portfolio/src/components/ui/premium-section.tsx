"use client";

import { MotionReveal } from "@/components/motion-reveal";
import { cn } from "@/components/ui/utils";

export function PremiumSection({
  id,
  children,
  className,
  header,
}: {
  id: string;
  children: React.ReactNode;
  className?: string;
  header?: React.ReactNode;
}) {
  return (
    <section id={id} className={cn("relative isolate overflow-hidden py-24", className)}>
      <div className="pointer-events-none absolute inset-0 bg-cyber-grid bg-gradient-drift" />
      <div className="pointer-events-none absolute inset-0 bg-faint-grid" />
      <div className="pointer-events-none absolute -top-24 left-1/2 h-48 w-[38rem] -translate-x-1/2 rounded-full bg-neon-blue/10 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-28 left-1/2 h-56 w-[44rem] -translate-x-1/2 rounded-full bg-neon-purple/10 blur-3xl" />

      <div className="relative mx-auto max-w-6xl px-4 sm:px-6">
        {header ? <div className="mb-12">{header}</div> : null}
        {children}
      </div>

      <div className="pointer-events-none absolute bottom-0 left-1/2 h-px w-[min(1100px,90vw)] -translate-x-1/2 glow-divider opacity-70" />
      <MotionReveal className="pointer-events-none absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-8 opacity-70">
        <div className="h-10 w-10 rounded-2xl border border-white/10 bg-white/5 shadow-neon-blue backdrop-blur-md dark:border-white/10" />
      </MotionReveal>
    </section>
  );
}
