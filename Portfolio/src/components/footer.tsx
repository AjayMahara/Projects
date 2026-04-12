import { SITE } from "@/data/portfolio";

export function Footer() {
  return (
    <footer className="border-t border-slate-200/70 bg-slate-50 py-10 text-sm text-slate-500 dark:border-white/5 dark:bg-cyber-bg dark:text-slate-500">
      <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-4 px-4 sm:flex-row sm:px-6">
        <p>
          © {new Date().getFullYear()} {SITE.name}. Crafted with Next.js & Three.js.
        </p>
        <div className="flex gap-4 font-mono text-xs">
          <a
            className="hover:text-neon-blue"
            href={SITE.github}
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
          <a
            className="hover:text-neon-blue"
            href={SITE.linkedin}
            target="_blank"
            rel="noreferrer"
          >
            LinkedIn
          </a>
        </div>
      </div>
    </footer>
  );
}
