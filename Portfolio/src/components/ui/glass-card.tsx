"use client";

import { motion } from "framer-motion";
import { cn } from "@/components/ui/utils";

export function GlassCard({
  children,
  className,
  glow = "blue",
  hoverLift = true,
}: {
  children: React.ReactNode;
  className?: string;
  glow?: "blue" | "purple" | "green";
  hoverLift?: boolean;
}) {
  const glowClass =
    glow === "green"
      ? "group-hover:bg-neon-green/20"
      : glow === "purple"
        ? "group-hover:bg-neon-purple/25"
        : "group-hover:bg-neon-blue/20";

  return (
    <motion.div
      whileHover={hoverLift ? { y: -6, scale: 1.01 } : undefined}
      transition={{ type: "spring", stiffness: 260, damping: 22 }}
      className={cn(
        "group glass relative overflow-hidden rounded-2xl p-6 sm:p-8",
        className,
      )}
    >
      <div
        className={cn(
          "pointer-events-none absolute -right-16 -top-16 h-44 w-44 rounded-full bg-neon-blue/10 blur-3xl transition duration-500",
          glowClass,
        )}
      />
      <div className="pointer-events-none absolute inset-0 opacity-0 transition group-hover:opacity-100">
        <div className="absolute inset-0 bg-gradient-to-br from-white/10 via-transparent to-white/5 dark:from-white/5" />
      </div>
      <div className="relative">{children}</div>
    </motion.div>
  );
}

