import { Hero } from "@/components/hero/hero";
import { AboutSection } from "@/components/sections/about-section";
import { ExperienceSection } from "@/components/sections/experience-section";
import { SkillsSection } from "@/components/sections/skills-section";
import { CyberPracticeSection } from "@/components/sections/cyber-practice-section";
import { ProjectsSection } from "@/components/sections/projects-section";
import { CertificationsSection } from "@/components/sections/certifications-section";
import { ContactSection } from "@/components/sections/contact-section";
import { Footer } from "@/components/footer";

export default function Home() {
  return (
    <>
      <Hero />
      <AboutSection />
      <ExperienceSection />
      <SkillsSection />
      <CyberPracticeSection />
      <ProjectsSection />
      <CertificationsSection />
      <ContactSection />
      <Footer />
    </>
  );
}
