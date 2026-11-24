export type LegalDocumentType = "privacy" | "terms";

export interface LegalBullet {
  lead?: string;
  text: string;
}

export interface LegalSection {
  id: string;
  number: string;
  title: string;
  paragraphs?: string[];
  bullets?: LegalBullet[];
  email?: string;
  hasCookieControls?: boolean;
}

export interface LegalDocumentData {
  title: string;
  effectiveDateLabel: string;
  effectiveDate: string;
  intro: string;
  sections: LegalSection[];
}

export interface LegalUiLabels {
  privacyPolicy: string;
  termsOfUse: string;
  backToHome: string;
  tableOfContents: string;
  cookieSettingsTitle: string;
  cookieSettingsDesc: string;
  essentialCookies: string;
  essentialCookiesDesc: string;
  alwaysActive: string;
  analyticsCookies: string;
  analyticsCookiesDesc: string;
  affiliateCookies: string;
  affiliateCookiesDesc: string;
  savePreferences: string;
  savedConfirmation: string;
  acceptAll: string;
  rejectOptional: string;
  manageCookies: string;
  lastUpdated: string;
  legalCenter: string;
  allRightsReserved: string;
}

export const SITE_LEGAL_INFO = {
  companyName: "Pezeex",
  domain: "pezeex.com",
  effectiveDate: "24/11/2026",
  contactEmail: "contact@pezeex.com",
};

/**
 * Menu & footer link labels for Privacy Policy and Terms of Use across all app languages.
 */
export const legalMenuTranslations: Record<string, { privacyPolicy: string; termsOfUse: string }> = {
  "العربية": { privacyPolicy: "سياسة الخصوصية", termsOfUse: "شروط الاستخدام" },
  "English": { privacyPolicy: "Privacy Policy", termsOfUse: "Terms of Use" },
  "हिन्दी": { privacyPolicy: "गोपनीयता नीति", termsOfUse: "उपयोग की शर्तें" },
  "中文 (普通话)": { privacyPolicy: "隐私政策", termsOfUse: "使用条款" },
  "Español": { privacyPolicy: "Política de Privacidad", termsOfUse: "Términos de Uso" },
  "Français": { privacyPolicy: "Politique de confidentialité", termsOfUse: "Conditions d'utilisation" },
  "Português": { privacyPolicy: "Política de Privacidade", termsOfUse: "Termos de Uso" },
  "Deutsch": { privacyPolicy: "Datenschutzerklärung", termsOfUse: "Nutzungsbedingungen" },
  "Nederlands": { privacyPolicy: "Privacybeleid", termsOfUse: "Gebruiksvoorwaarden" },
  "Polski": { privacyPolicy: "Polityka prywatności", termsOfUse: "Warunki korzystania" },
  "Srpski": { privacyPolicy: "Politika privatnosti", termsOfUse: "Uslovi korišćenja" },
  "Svenska": { privacyPolicy: "Integritetspolicy", termsOfUse: "Användarvillkor" },
  "Čeština": { privacyPolicy: "Zásady ochrany osobních údajů", termsOfUse: "Podmínky použití" },
  "Dansk": { privacyPolicy: "Privatlivspolitik", termsOfUse: "Brugsbetingelser" },
  "Norsk": { privacyPolicy: "Personvernerklæring", termsOfUse: "Bruksvilkår" },
  "Suomi": { privacyPolicy: "Tietosuojakäytäntö", termsOfUse: "Käyttöehdot" },
  "Ελληνικά": { privacyPolicy: "Πολιτική Απορρήτου", termsOfUse: "Όροι Χρήσης" },
  "Magyar": { privacyPolicy: "Adatvédelmi irányelvek", termsOfUse: "Felhasználási feltételek" },
  "Română": { privacyPolicy: "Politica de confidențialitate", termsOfUse: "Termeni de utilizare" },
  "Українська": { privacyPolicy: "Політика конфіденційності", termsOfUse: "Умови використання" },
  "Български": { privacyPolicy: "Политика за поверителност", termsOfUse: "Условия за ползване" },
  "Hrvatski": { privacyPolicy: "Pravila privatnosti", termsOfUse: "Uvjeti korištenja" },
  "Slovenčina": { privacyPolicy: "Zásady ochrany osobných údajov", termsOfUse: "Podmienky používania" },
  "Lietuvių": { privacyPolicy: "Privatumo politika", termsOfUse: "Naudojimo sąlygos" },
  "Slovenščina": { privacyPolicy: "Politika zasebnosti", termsOfUse: "Pogoji uporabe" },
  "Latviešu": { privacyPolicy: "Privātuma politika", termsOfUse: "Lietošanas noteikumi" },
  "Eesti": { privacyPolicy: "Privaatsuspoliitika", termsOfUse: "Kasutustingimused" },
  "Shqip": { privacyPolicy: "Politika e privatësisë", termsOfUse: "Kushtet e përdorimit" },
  "Bosanski": { privacyPolicy: "Politika privatnosti", termsOfUse: "Uslovi korištenja" },
  "Íslenska": { privacyPolicy: "Persónuverndarstefna", termsOfUse: "Notkunarskilmálar" },
  "日本語": { privacyPolicy: "プライバシーポリシー", termsOfUse: "利用規約" },
  "Русский": { privacyPolicy: "Политика конфиденциальности", termsOfUse: "Условия использования" },
  "اردو": { privacyPolicy: "رازداری کی پالیسی", termsOfUse: "استعمال کی شرائط" },
  "Türkçe": { privacyPolicy: "Gizlilik Politikası", termsOfUse: "Kullanım Şartları" },
  "Italiano": { privacyPolicy: "Informativa sulla privacy", termsOfUse: "Termini di utilizzo" },
  "한국어": { privacyPolicy: "개인정보 처리방침", termsOfUse: "이용약관" },
  "فارسی": { privacyPolicy: "سیاست حفظ حریم خصوصی", termsOfUse: "شرایط استفاده" },
};

export const legalUiLabels: LegalUiLabels = {
  privacyPolicy: "Privacy Policy",
  termsOfUse: "Terms of Use",
  backToHome: "Back to Pezeex",
  tableOfContents: "On this page",
  cookieSettingsTitle: "Cookie Preferences",
  cookieSettingsDesc: "Control how cookies and similar technologies are used during your visit to pezeex.com.",
  essentialCookies: "Essential Cookies",
  essentialCookiesDesc: "Required for core site functionality, language selection, and theme preferences.",
  alwaysActive: "Always active",
  analyticsCookies: "Analytics Cookies",
  analyticsCookiesDesc: "Help us understand traffic and improve Pezeex (e.g., Google Tag Manager / Google Analytics).",
  affiliateCookies: "Affiliate & Personalisation Cookies",
  affiliateCookiesDesc: "Used by affiliate partners (e.g., ConvertLink / Mitgo) to track product referrals and personalise offers.",
  savePreferences: "Save preferences",
  savedConfirmation: "Your cookie preferences have been saved.",
  acceptAll: "Accept all",
  rejectOptional: "Essential only",
  manageCookies: "Manage cookie preferences",
  lastUpdated: "Effective Date",
  legalCenter: "Legal & Compliance",
  allRightsReserved: "Pezeex. All rights reserved.",
};

export const legalDocuments: Record<LegalDocumentType, LegalDocumentData> = {
  privacy: {
    title: "Privacy Policy",
    effectiveDateLabel: "Effective Date",
    effectiveDate: SITE_LEGAL_INFO.effectiveDate,
    intro: `${SITE_LEGAL_INFO.companyName} ("we", "us", or "our") is committed to protecting your privacy. This Privacy Policy outlines how we collect, use, and safeguard your information when you use our AI-powered shopping assistant website ${SITE_LEGAL_INFO.domain} (the "Service").`,
    sections: [
      {
        id: "privacy-info-collect",
        number: "1",
        title: "What Information We Collect",
        bullets: [
          {
            lead: "Search Queries & Product Links",
            text: "Product names, descriptions, or URLs that you submit in our search bar so our AI can identify and suggest similar, lower-priced alternatives.",
          },
          {
            lead: "Technical & Location Data",
            text: "IP address (used to detect your approximate country so we can recommend relevant local stores), browser type, device information, and cookie data.",
          },
          {
            lead: "Usage & Local Storage Data",
            text: "Pages visited, click activity on product suggestions or affiliate links, and locally stored browser data (localStorage) such as your chosen language, theme mode, and daily search counter.",
          },
          {
            lead: "Direct Communications",
            text: "Your email address and message content if you choose to contact us directly by email.",
          },
        ],
      },
      {
        id: "privacy-how-use",
        number: "2",
        title: "How We Use Your Information",
        bullets: [
          { text: "To process product queries using AI and suggest similar, more affordable product alternatives and deals" },
          { text: "To tailor store suggestions to your approximate country and remember your language and display preferences" },
          { text: "To enforce daily fair-usage limits and protect the security and stability of the Service" },
          { text: "To analyse traffic, attribute affiliate referrals, and improve the Service" },
        ],
      },
      {
        id: "privacy-sharing",
        number: "3",
        title: "Sharing Your Information",
        paragraphs: ["We may share data with:"],
        bullets: [
          {
            lead: "AI service providers",
            text: "to analyze the product names or links you search for and generate shopping alternatives",
          },
          {
            lead: "Affiliate networks and partners",
            text: "(e.g., ConvertLink, Mitgo, and third-party merchants) to track outbound clicks and attribute affiliate referrals",
          },
          {
            lead: "Analytics and tag management services",
            text: "(e.g., Google Tag Manager and Google Analytics) to measure site traffic and performance",
          },
          {
            lead: "IP geolocation services",
            text: "(e.g., GeoJS) to detect your approximate country for localized store recommendations",
          },
        ],
      },
      {
        id: "privacy-cookies",
        number: "4",
        title: "Cookies & Local Storage",
        paragraphs: [
          "We use cookies, browser local storage (localStorage), and similar technologies to remember your language and theme settings, enforce daily search limits, measure traffic, and support affiliate tracking. You can manage your cookie preferences via your browser or our cookie settings below.",
        ],
        hasCookieControls: true,
      },
      {
        id: "privacy-rights",
        number: "5",
        title: "Your Privacy Rights (Europe & the Americas)",
        paragraphs: [
          "Depending on your region, you may exercise the following data protection rights under applicable laws in Europe and the Americas. We do not sell your personal information for monetary consideration.",
        ],
        bullets: [
          {
            lead: "Europe, UK & Switzerland (EU GDPR, UK GDPR & Swiss FADP)",
            text: "You have the right to access, correct, or delete personal data we hold about you, restrict or object to processing, withdraw consent at any time, and lodge a complaint with your local data protection authority (such as an EU/EEA supervisory authority or the UK ICO).",
          },
          {
            lead: "United States (CCPA / CPRA & Applicable State Laws)",
            text: "You have the right to know what categories of data we collect and share, request deletion of personal information, opt out of the sharing of data for cross-context behavioral tracking, and not be discriminated against for exercising your privacy rights.",
          },
          {
            lead: "Canada (PIPEDA & Provincial Privacy Laws)",
            text: "You have the right to access your personal information, request corrections, withdraw consent to non-essential processing, and raise concerns with the Office of the Privacy Commissioner of Canada.",
          },
          {
            lead: "Latin America (Brazil LGPD & Applicable Regional Laws)",
            text: "You have the right to confirm the existence of data processing, access and correct your data, request anonymization or deletion where applicable, and revoke consent under Brazil's LGPD and similar Latin American privacy frameworks.",
          },
          {
            lead: "International Data Transfers",
            text: "Because Pezeex relies on international AI, analytics, and affiliate infrastructure, technical and search query data may be processed outside your country of residence using appropriate contractual and technical safeguards.",
          },
        ],
      },
      {
        id: "privacy-retention",
        number: "6",
        title: "Data Retention",
        paragraphs: [
          "We retain your data only as long as necessary for the purposes outlined above.",
        ],
      },
      {
        id: "privacy-contact",
        number: "7",
        title: "Contact Us",
        paragraphs: ["If you have any questions, email us at:"],
        email: SITE_LEGAL_INFO.contactEmail,
      },
    ],
  },
  terms: {
    title: "Terms of Use",
    effectiveDateLabel: "Effective Date",
    effectiveDate: SITE_LEGAL_INFO.effectiveDate,
    intro: `Welcome to ${SITE_LEGAL_INFO.companyName}! These Terms of Use ("Terms") govern your use of our website ${SITE_LEGAL_INFO.domain} ("Service"), an AI-powered shopping assistant that helps users discover similar, lower-priced product alternatives, deals, and promotional offers across third-party online stores.`,
    sections: [
      {
        id: "terms-acceptance",
        number: "1",
        title: "Acceptance of Terms",
        paragraphs: [
          "By accessing or using our Service, you agree to these Terms. If you do not agree, do not use the Service.",
        ],
      },
      {
        id: "terms-description",
        number: "2",
        title: "Service Description",
        paragraphs: [
          "Pezeex uses artificial intelligence to analyze product names or links you submit and recommend similar, more affordable product alternatives, deals, and promotional offers sourced from third-party merchants and affiliate networks.",
        ],
      },
      {
        id: "terms-accuracy",
        number: "3",
        title: "Accuracy of Information",
        paragraphs: [
          "While we strive to ensure product suggestions, prices, and promotional offers are valid and up-to-date, AI-generated results may occasionally be inaccurate. We do not guarantee the accuracy, pricing, shipping terms, or availability of any product or offer. Merchants may change or discontinue listings and offers at any time.",
        ],
      },
      {
        id: "terms-conduct",
        number: "4",
        title: "User Conduct",
        paragraphs: ["You agree not to:"],
        bullets: [
          { text: "Use bots, scrapers, or automated tools to extract results or bypass daily search limits" },
          { text: "Attempt to hack, disrupt, overload, or exploit the Service" },
          { text: "Submit unlawful, harmful, or abusive content through the search interface" },
        ],
      },
      {
        id: "terms-ip",
        number: "5",
        title: "Intellectual Property",
        paragraphs: [
          `All content on the Service (logo, text, design) is owned by ${SITE_LEGAL_INFO.companyName} or licensed to us. You may not reproduce or redistribute any part of the site without permission.`,
        ],
      },
      {
        id: "terms-affiliate",
        number: "6",
        title: "Affiliate Disclosure",
        paragraphs: [
          "We may earn a commission if you click on an offer or complete a purchase through an affiliate link. This comes at no extra cost to you.",
        ],
      },
      {
        id: "terms-liability",
        number: "7",
        title: "Disclaimer of Liability",
        paragraphs: [
          "We do not guarantee any savings or the functionality of third-party websites linked via our Service. Use is at your own risk.",
        ],
      },
      {
        id: "terms-modifications",
        number: "8",
        title: "Modifications",
        paragraphs: [
          "We reserve the right to change these Terms at any time. Continued use of the Service indicates your acceptance of any updates.",
        ],
      },
      {
        id: "terms-law",
        number: "9",
        title: "Applicable Law & Consumer Rights",
        paragraphs: [
          "These Terms apply to the fullest extent permitted by applicable law. Nothing in these Terms limits or excludes any mandatory consumer protection, privacy, or statutory rights that apply to you under the laws of your country or jurisdiction of residence, including applicable consumer protection laws across Europe (EU, EEA, UK, and Switzerland) and the Americas (the United States, Canada, and Latin America).",
          "If any provision of these Terms is found to be invalid or unenforceable under mandatory local law, the remaining provisions shall continue in full force and effect.",
        ],
      },
      {
        id: "terms-contact",
        number: "10",
        title: "Contact Us",
        paragraphs: ["For legal queries or feedback, email us at:"],
        email: SITE_LEGAL_INFO.contactEmail,
      },
    ],
  },
};
