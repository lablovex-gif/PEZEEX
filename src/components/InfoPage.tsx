import { ArrowLeft, Globe, Instagram, Mail, ShieldCheck, Sparkles, Tag, Heart } from "lucide-react";
import { SITE_LEGAL_INFO } from "../lib/legalContent";

export type InfoPageType = "about" | "contact";

interface InfoPageProps {
  page: InfoPageType;
  onNavigate: (target: "home" | "about" | "contact" | "privacy" | "terms") => void;
}

export function InfoPage({ page, onNavigate }: InfoPageProps) {
  const isAbout = page === "about";

  return (
    <main
      dir="ltr"
      lang="en"
      className="flex-1 w-full overflow-y-auto custom-scrollbar bg-background text-foreground text-left"
    >
      <div className="max-w-4xl mx-auto px-5 sm:px-8 py-8 sm:py-12">
        {/* Top Utility Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-border">
          <button
            type="button"
            onClick={() => onNavigate("home")}
            className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors whitespace-nowrap shrink-0 min-h-10 cursor-pointer"
          >
            <ArrowLeft size={16} />
            <span>Back to Pezeex</span>
          </button>

          <nav aria-label="Company pages" className="inline-flex items-center gap-1 p-1 rounded-lg bg-muted border border-border/60">
            <a
              href="/about"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("about");
              }}
              className={`px-3.5 py-1.5 text-xs sm:text-sm font-medium rounded-md transition-colors whitespace-nowrap ${
                isAbout ? "bg-background text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              About
            </a>
            <a
              href="/contact"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("contact");
              }}
              className={`px-3.5 py-1.5 text-xs sm:text-sm font-medium rounded-md transition-colors whitespace-nowrap ${
                !isAbout ? "bg-background text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground"
              }`}
            >
              Contact
            </a>
          </nav>
        </div>

        {isAbout ? (
          <article className="py-8 sm:py-10 space-y-10">
            <header className="pb-8 border-b border-border">
              <div className="text-xs text-muted-foreground mb-3">
                {SITE_LEGAL_INFO.companyName} · {SITE_LEGAL_INFO.domain}
              </div>
              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-foreground mb-4">
                About Pezeex
              </h1>
              <p className="text-base text-muted-foreground leading-relaxed max-w-2xl">
                Don&apos;t pay more than you should. Pezeex is an AI-powered shopping assistant that helps you discover similar, lower-priced alternatives to the products you love across trusted global and local online stores.
              </p>
            </header>

            <section className="grid grid-cols-1 sm:grid-cols-3 gap-6">
              <div className="p-5 rounded-xl border border-border bg-card space-y-2">
                <Sparkles size={20} className="text-foreground" />
                <h2 className="text-base font-semibold text-foreground">AI Product Matching</h2>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Enter any product name, model number, or store link to compare specs and find more affordable alternatives in seconds.
                </p>
              </div>
              <div className="p-5 rounded-xl border border-border bg-card space-y-2">
                <Globe size={20} className="text-foreground" />
                <h2 className="text-base font-semibold text-foreground">25+ Countries &amp; 37 Languages</h2>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Recommendations adapt to your region, currency, and preferred language across major international and regional retailers.
                </p>
              </div>
              <div className="p-5 rounded-xl border border-border bg-card space-y-2">
                <Tag size={20} className="text-foreground" />
                <h2 className="text-base font-semibold text-foreground">Free &amp; Transparent</h2>
                <p className="text-sm text-muted-foreground leading-relaxed">
                  Enjoy up to 25 free searches every day. We may earn a small affiliate commission on partner links at zero extra cost to you.
                </p>
              </div>
            </section>

            <section className="space-y-3 max-w-[70ch]">
              <h2 className="text-xl font-semibold text-foreground">How Pezeex Works</h2>
              <p className="text-[15px] leading-7 text-foreground/85">
                Online prices can vary dramatically between flagship brands and comparable alternatives with similar specifications. Pezeex analyzes the product you are considering and searches for lower-priced matches across reputable retailers tailored to your location.
              </p>
              <p className="text-[15px] leading-7 text-foreground/85">
                Because merchant pricing and inventory change frequently, always confirm final prices, shipping costs, and return policies directly on the retailer&apos;s page before purchasing.
              </p>
            </section>

            <section className="space-y-3 max-w-[70ch]">
              <h2 className="text-xl font-semibold text-foreground">Get in Touch</h2>
              <p className="text-[15px] leading-7 text-foreground/85">
                Have feedback, store suggestions, or partnership questions? Email us anytime at{" "}
                <a
                  href={`mailto:${SITE_LEGAL_INFO.contactEmail}`}
                  className="font-semibold text-foreground underline underline-offset-4 hover:opacity-75"
                >
                  {SITE_LEGAL_INFO.contactEmail}
                </a>
                .
              </p>
            </section>
          </article>
        ) : (
          <article className="py-8 sm:py-10 space-y-10">
            <header className="pb-8 border-b border-border">
              <div className="text-xs text-muted-foreground mb-3">
                {SITE_LEGAL_INFO.companyName} · {SITE_LEGAL_INFO.domain}
              </div>
              <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-foreground mb-4">
                Contact Pezeex
              </h1>
              <p className="text-base text-muted-foreground leading-relaxed max-w-2xl">
                Have a question, partnership inquiry, privacy request, or product suggestion? Reach the Pezeex team directly through email or our official channels below.
              </p>
            </header>

            <section className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <a
                href={`mailto:${SITE_LEGAL_INFO.contactEmail}`}
                className="flex items-center gap-4 p-5 rounded-xl border border-border bg-card hover:bg-muted/50 transition-colors"
              >
                <div className="w-11 h-11 rounded-full bg-primary/10 flex items-center justify-center text-foreground shrink-0">
                  <Mail size={20} />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-foreground">Email Support &amp; Inquiries</h2>
                  <p className="text-sm text-muted-foreground truncate">{SITE_LEGAL_INFO.contactEmail}</p>
                </div>
              </a>

              <a
                href="https://www.instagram.com/itti_fc4321"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-4 p-5 rounded-xl border border-border bg-card hover:bg-muted/50 transition-colors"
              >
                <div className="w-11 h-11 rounded-full bg-primary/10 flex items-center justify-center text-foreground shrink-0">
                  <Instagram size={20} />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-foreground">Instagram</h2>
                  <p className="text-sm text-muted-foreground truncate">@itti_fc4321</p>
                </div>
              </a>

              <a
                href="https://www.reddit.com/user/ExternalAd2358"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-4 p-5 rounded-xl border border-border bg-card hover:bg-muted/50 transition-colors"
              >
                <div className="w-11 h-11 rounded-full bg-primary/10 flex items-center justify-center text-foreground shrink-0">
                  <Globe size={20} />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-foreground">Reddit</h2>
                  <p className="text-sm text-muted-foreground truncate">u/ExternalAd2358</p>
                </div>
              </a>

              <a
                href="https://paypal.me/AbdullahAlbukhari37"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-4 p-5 rounded-xl border border-border bg-card hover:bg-muted/50 transition-colors"
              >
                <div className="w-11 h-11 rounded-full bg-primary/10 flex items-center justify-center text-foreground shrink-0">
                  <Heart size={20} />
                </div>
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold text-foreground">Support Pezeex</h2>
                  <p className="text-sm text-muted-foreground truncate">paypal.me/AbdullahAlbukhari37</p>
                </div>
              </a>
            </section>
          </article>
        )}

        {/* Shared Footer */}
        <footer className="pt-8 border-t border-border flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <ShieldCheck size={15} className="shrink-0" />
            <span>© {new Date().getFullYear()} Pezeex. All rights reserved.</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <a
              href={`mailto:${SITE_LEGAL_INFO.contactEmail}`}
              className="hover:text-foreground transition-colors"
            >
              {SITE_LEGAL_INFO.contactEmail}
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="/about"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("about");
              }}
              className={`hover:text-foreground transition-colors ${isAbout ? "text-foreground font-semibold" : ""}`}
            >
              About
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="/contact"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("contact");
              }}
              className={`hover:text-foreground transition-colors ${!isAbout ? "text-foreground font-semibold" : ""}`}
            >
              Contact
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="/privacy-policy"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("privacy");
              }}
              className="hover:text-foreground transition-colors"
            >
              Privacy Policy
            </a>
            <span aria-hidden="true">·</span>
            <a
              href="/terms-of-use"
              onClick={(e) => {
                e.preventDefault();
                onNavigate("terms");
              }}
              className="hover:text-foreground transition-colors"
            >
              Terms of Use
            </a>
          </div>
        </footer>
      </div>
    </main>
  );
}
