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
  analyticsCookiesDesc: "Help us understand traffic and improve Pezeex (e.g., Google Analytics).",
  affiliateCookies: "Affiliate & Personalisation Cookies",
  affiliateCookiesDesc: "Used by affiliate partners to track discount code usage and personalise offers.",
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
    intro: `${SITE_LEGAL_INFO.companyName} ("we", "us", or "our") is committed to protecting your privacy. This Privacy Policy outlines how we collect, use, and safeguard your information when you use our website ${SITE_LEGAL_INFO.domain} (the "Service").`,
    sections: [
      {
        id: "privacy-info-collect",
        number: "1",
        title: "What Information We Collect",
        bullets: [
          {
            lead: "Personal Data",
            text: "We may collect your name, email address, and preferences if you sign up for our newsletter or promotions.",
          },
          {
            lead: "Technical Data",
            text: "Includes IP address, browser type, device information, and cookie data.",
          },
          {
            lead: "Usage Data",
            text: "Pages visited, click activity (e.g., clicking a promo code), time spent on site.",
          },
        ],
      },
      {
        id: "privacy-how-use",
        number: "2",
        title: "How We Use Your Information",
        bullets: [
          { text: "To provide access to discount codes and promotions" },
          { text: "To personalise your user experience" },
          { text: "To send newsletters and marketing communications (only with consent)" },
          { text: "To analyse traffic and improve the Service" },
        ],
      },
      {
        id: "privacy-sharing",
        number: "3",
        title: "Sharing Your Information",
        paragraphs: ["We may share data with:"],
        bullets: [
          {
            lead: "Affiliate partners",
            text: "to track coupon usage and provide rewards",
          },
          {
            lead: "Analytics services",
            text: "(e.g., Google Analytics)",
          },
          {
            lead: "Email marketing providers",
            text: "(e.g., Mailchimp), if you've opted in",
          },
        ],
      },
      {
        id: "privacy-cookies",
        number: "4",
        title: "Cookies",
        paragraphs: [
          "We use cookies and similar technologies to enhance your experience. You can manage your cookie preferences via your browser or our cookie settings below.",
        ],
        hasCookieControls: true,
      },
      {
        id: "privacy-rights",
        number: "5",
        title: "Your Rights (under UK GDPR)",
        bullets: [
          { text: "Access the data we hold about you" },
          { text: "Request correction or deletion" },
          { text: "Withdraw consent at any time" },
          { text: "File a complaint with the UK ICO (Information Commissioner's Office)" },
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
    intro: `Welcome to ${SITE_LEGAL_INFO.companyName}! These Terms of Use ("Terms") govern your use of our website ${SITE_LEGAL_INFO.domain} ("Service"), which provides digital coupons and promotional codes.`,
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
          "We offer discount codes and promotional offers sourced from third-party merchants and affiliate networks.",
        ],
      },
      {
        id: "terms-accuracy",
        number: "3",
        title: "Accuracy of Information",
        paragraphs: [
          "While we strive to ensure offers are valid and up-to-date, we do not guarantee the accuracy or availability of any offer. Merchants may change or discontinue offers at any time.",
        ],
      },
      {
        id: "terms-conduct",
        number: "4",
        title: "User Conduct",
        paragraphs: ["You agree not to:"],
        bullets: [
          { text: "Use bots or automated tools to scrape coupon codes" },
          { text: "Attempt to hack, disrupt, or exploit the site" },
          { text: "Post false or misleading user reviews (if applicable)" },
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
        title: "Governing Law",
        paragraphs: ["These Terms are governed by the laws of England and Wales."],
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
