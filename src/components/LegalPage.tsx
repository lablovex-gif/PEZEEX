import { useState } from "react";
import { ArrowLeft, Check, Mail, ShieldCheck, FileText } from "lucide-react";
import {
  LegalDocumentType,
  legalDocuments,
  legalUiLabels,
  SITE_LEGAL_INFO,
} from "../lib/legalContent";

interface CookiePreferences {
  essential: true;
  analytics: boolean;
  affiliate: boolean;
  updatedAt?: string;
}

const COOKIE_STORAGE_KEY = "pezeex_cookie_preferences";

function loadCookiePreferences(): CookiePreferences {
  try {
    const raw = localStorage.getItem(COOKIE_STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        essential: true,
        analytics: Boolean(parsed.analytics),
        affiliate: Boolean(parsed.affiliate),
        updatedAt: typeof parsed.updatedAt === "string" ? parsed.updatedAt : undefined,
      };
    }
  } catch {
    // Ignore storage read failures
  }
  return {
    essential: true,
    analytics: true,
    affiliate: true,
  };
}

interface LegalPageProps {
  activeTab: LegalDocumentType;
  onSelectTab: (tab: LegalDocumentType) => void;
  onBack: () => void;
}

export function LegalPage({
  activeTab,
  onSelectTab,
  onBack,
}: LegalPageProps) {
  const [cookiePrefs, setCookiePrefs] = useState<CookiePreferences>(() => loadCookiePreferences());
  const [cookieSaved, setCookieSaved] = useState(false);

  const ui = legalUiLabels;
  const doc = legalDocuments[activeTab];

  const persistCookiePrefs = (next: CookiePreferences) => {
    const payload: CookiePreferences = {
      ...next,
      essential: true,
      updatedAt: new Date().toISOString(),
    };
    setCookiePrefs(payload);
    try {
      localStorage.setItem(COOKIE_STORAGE_KEY, JSON.stringify(payload));
    } catch {
      // Ignore storage write failures
    }
    setCookieSaved(true);
    window.setTimeout(() => setCookieSaved(false), 3000);
  };

  const scrollToSection = (sectionId: string) => {
    const el = document.getElementById(sectionId);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  return (
    <main
      dir="ltr"
      lang="en"
      className="flex-1 w-full overflow-y-auto custom-scrollbar bg-background text-foreground text-left"
    >
      <div className="max-w-5xl mx-auto px-5 sm:px-8 py-8 sm:py-12">
        {/* Top Utility Navigation Row */}
        <div className="flex flex-wrap items-center justify-between gap-4 pb-6 border-b border-border">
          <button
            type="button"
            onClick={onBack}
            className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors whitespace-nowrap shrink-0 min-h-10 cursor-pointer"
          >
            <ArrowLeft size={16} />
            <span>{ui.backToHome}</span>
          </button>

          {/* Document Type Segmented Control */}
          <div
            role="tablist"
            aria-label={ui.legalCenter}
            className="inline-flex items-center gap-1 p-1 rounded-lg bg-muted border border-border/60"
          >
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "privacy"}
              onClick={() => onSelectTab("privacy")}
              className={`px-3.5 py-1.5 text-xs sm:text-sm font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === "privacy"
                  ? "bg-background text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {ui.privacyPolicy}
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === "terms"}
              onClick={() => onSelectTab("terms")}
              className={`px-3.5 py-1.5 text-xs sm:text-sm font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeTab === "terms"
                  ? "bg-background text-foreground shadow-xs"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {ui.termsOfUse}
            </button>
          </div>
        </div>

        {/* Document Header */}
        <header className="py-8 sm:py-10 border-b border-border">
          <div className="flex items-center gap-2 text-xs text-muted-foreground mb-3">
            <span>{ui.legalCenter}</span>
            <span aria-hidden="true">·</span>
            <span>{SITE_LEGAL_INFO.domain}</span>
            <span aria-hidden="true">·</span>
            <span className="tabular-nums">
              {doc.effectiveDateLabel}: {doc.effectiveDate}
            </span>
          </div>

          <h1 className="text-3xl sm:text-4xl font-bold tracking-tight text-foreground text-balance mb-4">
            {doc.title}
          </h1>

          <p className="text-base text-muted-foreground leading-relaxed max-w-3xl">
            {doc.intro}
          </p>
        </header>

        {/* Two-Column Editorial Layout: Sticky TOC + Structured Legal Content */}
        <div className="grid grid-cols-1 lg:grid-cols-[240px_1fr] gap-8 lg:gap-12 py-8 sm:py-10 items-start">
          {/* Sticky Sidebar Table of Contents */}
          <aside className="lg:sticky lg:top-6">
            <h2 className="text-xs font-semibold text-muted-foreground mb-3">
              {ui.tableOfContents}
            </h2>
            <nav aria-label={ui.tableOfContents} className="flex flex-col gap-1">
              {doc.sections.map((section) => (
                <button
                  key={section.id}
                  type="button"
                  onClick={() => scrollToSection(section.id)}
                  className="py-2 px-2.5 rounded-md text-sm text-left text-muted-foreground hover:text-foreground hover:bg-muted/60 transition-colors cursor-pointer"
                >
                  <span className="tabular-nums opacity-60 mr-1.5">{section.number}.</span>
                  <span>{section.title}</span>
                </button>
              ))}
            </nav>
          </aside>

          {/* Main Legal Prose */}
          <article className="space-y-10 min-w-0">
            {doc.sections.map((section) => (
              <section
                key={section.id}
                id={section.id}
                className="scroll-mt-6 pb-8 border-b border-border/60 last:border-b-0 last:pb-0"
              >
                <h2 className="text-lg sm:text-xl font-semibold text-foreground mb-3.5 tracking-tight">
                  <span className="tabular-nums text-muted-foreground mr-2">
                    {section.number}.
                  </span>
                  {section.title}
                </h2>

                {section.paragraphs && (
                  <div className="space-y-3 text-[15px] leading-7 text-foreground/85 max-w-[70ch]">
                    {section.paragraphs.map((paragraph, idx) => (
                      <p key={idx}>{paragraph}</p>
                    ))}
                  </div>
                )}

                {section.bullets && (
                  <ul className="mt-3 space-y-2.5 text-[15px] leading-7 text-foreground/85 max-w-[70ch] list-disc pl-5">
                    {section.bullets.map((item, idx) => (
                      <li key={idx}>
                        {item.lead ? (
                          <>
                            <strong className="font-semibold text-foreground">{item.lead}:</strong>{" "}
                            {item.text}
                          </>
                        ) : (
                          item.text
                        )}
                      </li>
                    ))}
                  </ul>
                )}

                {section.email && (
                  <div className="mt-4 flex flex-wrap items-center gap-4">
                    <a
                      href={`mailto:${section.email}`}
                      className="inline-flex items-center gap-2 text-sm font-semibold text-foreground underline underline-offset-4 hover:opacity-75 transition-opacity"
                    >
                      <Mail size={16} className="shrink-0" />
                      <span>{section.email}</span>
                    </a>
                  </div>
                )}

                {/* Interactive Cookie Preferences Panel for Section 4 */}
                {section.hasCookieControls && (
                  <div className="mt-6 p-5 sm:p-6 rounded-xl bg-card border border-border space-y-5">
                    <div>
                      <h3 className="text-base font-semibold text-foreground">
                        {ui.cookieSettingsTitle}
                      </h3>
                      <p className="text-sm text-muted-foreground mt-1 leading-relaxed">
                        {ui.cookieSettingsDesc}
                      </p>
                    </div>

                    <div className="divide-y divide-border/70">
                      {/* Essential */}
                      <div className="py-3.5 flex items-center justify-between gap-4">
                        <div className="min-w-0">
                          <div className="text-sm font-medium text-foreground">
                            {ui.essentialCookies}
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {ui.essentialCookiesDesc}
                          </p>
                        </div>
                        <span className="text-xs font-medium text-muted-foreground whitespace-nowrap shrink-0">
                          {ui.alwaysActive}
                        </span>
                      </div>

                      {/* Analytics */}
                      <div className="py-3.5 flex items-center justify-between gap-4">
                        <div className="min-w-0">
                          <label
                            htmlFor="cookie-analytics-toggle"
                            className="text-sm font-medium text-foreground cursor-pointer"
                          >
                            {ui.analyticsCookies}
                          </label>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {ui.analyticsCookiesDesc}
                          </p>
                        </div>
                        <input
                          id="cookie-analytics-toggle"
                          type="checkbox"
                          checked={cookiePrefs.analytics}
                          onChange={(e) =>
                            setCookiePrefs((prev) => ({
                              ...prev,
                              analytics: e.target.checked,
                            }))
                          }
                          className="h-5 w-5 accent-primary rounded cursor-pointer shrink-0"
                        />
                      </div>

                      {/* Affiliate & Personalisation */}
                      <div className="py-3.5 flex items-center justify-between gap-4">
                        <div className="min-w-0">
                          <label
                            htmlFor="cookie-affiliate-toggle"
                            className="text-sm font-medium text-foreground cursor-pointer"
                          >
                            {ui.affiliateCookies}
                          </label>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            {ui.affiliateCookiesDesc}
                          </p>
                        </div>
                        <input
                          id="cookie-affiliate-toggle"
                          type="checkbox"
                          checked={cookiePrefs.affiliate}
                          onChange={(e) =>
                            setCookiePrefs((prev) => ({
                              ...prev,
                              affiliate: e.target.checked,
                            }))
                          }
                          className="h-5 w-5 accent-primary rounded cursor-pointer shrink-0"
                        />
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <button
                          type="button"
                          onClick={() => persistCookiePrefs(cookiePrefs)}
                          className="px-4 py-2 text-xs sm:text-sm font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {ui.savePreferences}
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            persistCookiePrefs({
                              essential: true,
                              analytics: true,
                              affiliate: true,
                            })
                          }
                          className="px-4 py-2 text-xs sm:text-sm font-medium rounded-lg border border-border bg-background text-foreground hover:bg-muted transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {ui.acceptAll}
                        </button>
                        <button
                          type="button"
                          onClick={() =>
                            persistCookiePrefs({
                              essential: true,
                              analytics: false,
                              affiliate: false,
                            })
                          }
                          className="px-4 py-2 text-xs sm:text-sm font-medium rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                        >
                          {ui.rejectOptional}
                        </button>
                      </div>

                      {cookieSaved && (
                        <div
                          role="status"
                          className="inline-flex items-center gap-1.5 text-xs font-medium text-foreground"
                        >
                          <Check size={14} className="shrink-0" />
                          <span>{ui.savedConfirmation}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </section>
            ))}

            {/* Clean Legal Footer Summary */}
            <footer className="pt-8 border-t border-border flex flex-wrap items-center justify-between gap-4 text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                {activeTab === "privacy" ? (
                  <ShieldCheck size={15} className="shrink-0" />
                ) : (
                  <FileText size={15} className="shrink-0" />
                )}
                <span>
                  © {new Date().getFullYear()} {ui.allRightsReserved}
                </span>
              </div>

              <div className="flex items-center gap-3">
                <a
                  href="/privacy-policy"
                  onClick={(e) => {
                    e.preventDefault();
                    onSelectTab("privacy");
                  }}
                  className={`hover:text-foreground transition-colors ${
                    activeTab === "privacy" ? "text-foreground font-semibold" : ""
                  }`}
                >
                  {ui.privacyPolicy}
                </a>
                <span aria-hidden="true">·</span>
                <a
                  href="/terms-of-use"
                  onClick={(e) => {
                    e.preventDefault();
                    onSelectTab("terms");
                  }}
                  className={`hover:text-foreground transition-colors ${
                    activeTab === "terms" ? "text-foreground font-semibold" : ""
                  }`}
                >
                  {ui.termsOfUse}
                </a>
              </div>
            </footer>
          </article>
        </div>
      </div>
    </main>
  );
}
