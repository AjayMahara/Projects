# Ajay Mahara — Portfolio

A modern, cybersecurity-inspired personal portfolio built with **Next.js (App Router)**, **TypeScript**, **Tailwind CSS**, **Framer Motion**, and **React Three Fiber** / **Three.js**.

## Prerequisites

- Node.js **18.18+** (recommended: **20 LTS**)
- npm **10+** (or pnpm / yarn)

## Run locally

```bash
cd "/Users/mmt12065/Documents/Portfolio V2"
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Scripts

| Command        | Description              |
| -------------- | ------------------------ |
| `npm run dev`  | Dev server (Turbopack)   |
| `npm run build` | Production build        |
| `npm run start` | Start production server |
| `npm run lint`  | ESLint                   |

## Customize content

Edit **`src/data/portfolio.ts`** for name, links, canonical **`SITE.url`**, experience, projects, certifications, and practice stats. Replace placeholder email, LinkedIn, and GitHub URLs.

## Tech notes

- The 3D hero uses a **client-only** Canvas (`dynamic(..., { ssr: false })`) to avoid hydration mismatches.
- Pixel ratio is capped for smoother performance on high-DPI displays.
- Theme preference is stored in **`localStorage`** under `portfolio-theme`.

## License

Private portfolio project — adjust as you prefer.
