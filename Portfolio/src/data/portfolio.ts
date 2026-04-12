export const SITE = {
  name: "Ajay Mahara",
  title: "SRE Engineer || Cybersecurity Practicioner",
  url: "https://ajaymahara.dev",
  tagline:
    "Securing systems with an SRE mindset — monitoring, detecting, and defending at scale.",
  email: "ajay.mahara@example.com",
  linkedin: "https://www.linkedin.com/in/ajay-mahara",
  github: "https://github.com/ajaymahara",
  roles: [
    "SOC Analyst",
    "Security Engineer",
    "Blue Team",
    "SRE",
    "Incident Responder",
  ],
} as const;

export const aboutCards = [
  {
    title: "Monitoring",
    description:
      "Deep experience with observability stacks: metrics, logs, traces, and actionable alerting at scale.",
    icon: "chart",
  },
  {
    title: "Incident Response",
    description:
      "Structured triage, war-room coordination, RCA, and postmortems that turn outages into resilience.",
    icon: "shield",
  },
  {
    title: "Security Learning",
    description:
      "Hands-on labs, CTF-style practice, and continuous upskill toward defensive security operations.",
    icon: "lock",
  },
] as const;

export const experience = [
  {
    company: "MakeMyTrip",
    role: "Site Reliability Engineer",
    period: "Present",
    highlights: [
      "Owned reliability for high-traffic services with SLO-driven operations.",
      "Built and tuned monitoring with Zabbix, Grafana, and AWS CloudWatch.",
      "Led incident response, RCA, and blameless postmortems.",
      "Multi-cloud cost optimization across AWS, GCP, and Azure footprints.",
      "Applied security hardening patterns: least privilege, secrets hygiene, and network controls.",
    ],
  },
] as const;

export const skills = {
  Programming: [
    { name: "Python", level: 90 },
    { name: "C++", level: 75 },
    { name: "Bash", level: 88 },
  ],
  Tools: [
    { name: "Splunk", level: 82 },
    { name: "Grafana", level: 92 },
    { name: "Zabbix", level: 88 },
    { name: "Akamai", level: 70 },
  ],
  Cloud: [
    { name: "AWS", level: 90 },
    { name: "GCP", level: 78 },
    { name: "Azure", level: 72 },
  ],
  Security: [
    { name: "TryHackMe", level: 88 },
    { name: "HackTheBox", level: 80 },
  ],
} as const;

export const cyberStats = {
  tryhackme: { rank: "Top 3%", rooms: 42, badges: 12 },
  htb: { machines: 8, challenges: 24 },
  terminalLines: [
    "thm-stats --profile ajay",
    "rooms_completed: 42",
    "badges_earned: 12",
    "focus: blue_team fundamentals",
    
  ],
} as const;

export const projects = [
  {
    title: "Malware Detection using ML",
    description:
      "Feature engineering on PE headers and behavioral signals with classical and ensemble models for triage-grade classification.",
    stack: ["Python", "scikit-learn", "pandas", "Jupyter"],
    github: "https://github.com/ajaymahara/malware-ml",
  },
  {
    title: "Image Steganography",
    description:
      "LSB-based embed/extract pipeline with perceptual quality checks and simple detection heuristics for education.",
    stack: ["Python", "OpenCV", "NumPy"],
    github: "https://github.com/ajaymahara/image-stego",
  },
] as const;

export const certifications = [
  {
    name: "AWS Certified Cloud Practitioner",
    issuer: "Amazon Web Services",
    year: "2024",
  },
  {
    name: "Certified Ethical Hacker (CEH)",
    issuer: "EC-Council",
    year: "2024",
  },
] as const;
