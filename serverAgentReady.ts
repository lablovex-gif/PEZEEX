export type PageRouteKey = "home" | "about" | "contact" | "privacy" | "terms";

export const SITE_URL = "https://pezeex.com";
export const SITE_NAME = "Pezeex";
export const CONTACT_EMAIL = "contact@pezeex.com";
export const LAST_MODIFIED = "2026-11-26";

export const SAME_AS_PROFILES = [
  "https://www.instagram.com/itti_fc4321",
  "https://www.reddit.com/user/ExternalAd2358",
  "https://paypal.me/AbdullahAlbukhari37",
];

export interface PageMeta {
  key: PageRouteKey;
  path: string;
  canonicalUrl: string;
  markdownPath: string;
  title: string;
  description: string;
}

export const PAGE_METADATA: Record<PageRouteKey, PageMeta> = {
  home: {
    key: "home",
    path: "/",
    canonicalUrl: `${SITE_URL}/`,
    markdownPath: "/index.md",
    title: "Pezeex | AI Shopping Assistant for Cheaper Alternatives",
    description:
      "Find similar, lower-priced product alternatives across trusted online stores with Pezeex AI shopping assistant. Paste any product name or link to save money.",
  },
  about: {
    key: "about",
    path: "/about",
    canonicalUrl: `${SITE_URL}/about`,
    markdownPath: "/about.md",
    title: "About Pezeex | AI Shopping Assistant",
    description:
      "Learn how Pezeex uses AI to discover comparable, more affordable product alternatives across global and regional online stores in 25+ countries.",
  },
  contact: {
    key: "contact",
    path: "/contact",
    canonicalUrl: `${SITE_URL}/contact`,
    markdownPath: "/contact.md",
    title: "Contact Pezeex | Support & Inquiries",
    description:
      "Contact the Pezeex team at contact@pezeex.com for support, partnerships, privacy requests, or feedback, or connect on Instagram and Reddit.",
  },
  privacy: {
    key: "privacy",
    path: "/privacy-policy",
    canonicalUrl: `${SITE_URL}/privacy-policy`,
    markdownPath: "/privacy-policy.md",
    title: "Privacy Policy | Pezeex",
    description:
      "Read the Pezeex Privacy Policy covering search queries, approximate country detection, cookies, GDPR/CCPA/PIPEDA/LGPD privacy rights, and contact details.",
  },
  terms: {
    key: "terms",
    path: "/terms-of-use",
    canonicalUrl: `${SITE_URL}/terms-of-use`,
    markdownPath: "/terms-of-use.md",
    title: "Terms of Use | Pezeex",
    description:
      "Review the Pezeex Terms of Use covering AI product suggestions, affiliate disclosure, fair-usage limits, consumer rights, and legal contact information.",
  },
};

export const ROBOTS_TXT = `# Pezeex Robots & Content Signals Policy
User-agent: *
Content-Signal: search=yes, ai-input=yes, ai-train=no
Allow: /
Disallow: /api/

Sitemap: ${SITE_URL}/sitemap.xml
`;

export const SITEMAP_XML = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${SITE_URL}/</loc>
    <lastmod>${LAST_MODIFIED}</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>${SITE_URL}/about</loc>
    <lastmod>${LAST_MODIFIED}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${SITE_URL}/contact</loc>
    <lastmod>${LAST_MODIFIED}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  <url>
    <loc>${SITE_URL}/privacy-policy</loc>
    <lastmod>${LAST_MODIFIED}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
  <url>
    <loc>${SITE_URL}/terms-of-use</loc>
    <lastmod>${LAST_MODIFIED}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.6</priority>
  </url>
</urlset>
`;

export const LLMS_TXT = `# Pezeex

> Pezeex is an AI-powered shopping assistant that finds similar, lower-priced product alternatives across trusted global and regional online stores.

Enter any product name or paste a product link to discover more affordable alternatives tailored to your country, currency, and preferred language. Pezeex supports 25+ countries and 37 languages with up to 25 free searches per day.

## Key Pages

- [Home](${SITE_URL}/): Interactive AI shopping assistant for searching cheaper product alternatives by name or URL.
- [About Pezeex](${SITE_URL}/about): Overview of how Pezeex works, supported shopping regions, and affiliate transparency.
- [Contact Us](${SITE_URL}/contact): Direct email support at ${CONTACT_EMAIL} and official social channels.
- [Privacy Policy](${SITE_URL}/privacy-policy): Information collected, cookies, GDPR/CCPA/PIPEDA/LGPD rights, and data retention.
- [Terms of Use](${SITE_URL}/terms-of-use): Terms governing use of pezeex.com, AI accuracy notice, and affiliate disclosure.

## Agent & Machine-Readable Resources

- [Homepage in Markdown](${SITE_URL}/index.md): Token-efficient Markdown version of the homepage (also returned at \`/\` when requesting \`Accept: text/markdown\`).
- [About in Markdown](${SITE_URL}/about.md): Markdown version of the About page.
- [Contact in Markdown](${SITE_URL}/contact.md): Markdown version of the Contact page.
- [MCP Server Card](${SITE_URL}/.well-known/mcp/server-card.json): SEP-1649 Model Context Protocol discovery card for Pezeex.
- [MCP Endpoint](${SITE_URL}/api/mcp): Streamable HTTP JSON-RPC 2.0 MCP endpoint exposing \`search_product_alternatives\` and \`get_supported_countries\`.
- [XML Sitemap](${SITE_URL}/sitemap.xml): Machine-readable index of all public pages.

## Contact & Official Profiles

- Email: [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL})
- Instagram: [https://www.instagram.com/itti_fc4321](https://www.instagram.com/itti_fc4321)
- Reddit: [https://www.reddit.com/user/ExternalAd2358](https://www.reddit.com/user/ExternalAd2358)
- Support Pezeex: [https://paypal.me/AbdullahAlbukhari37](https://paypal.me/AbdullahAlbukhari37)
`;

export const MCP_SERVER_CARD = {
  $schema: "https://static.modelcontextprotocol.io/schemas/mcp-server-card/v1.json",
  version: "1.0",
  protocolVersion: "2025-06-18",
  name: "pezeex-shopping-assistant",
  description:
    "AI-powered shopping assistant that discovers similar, lower-priced product alternatives across trusted global and regional online stores.",
  endpoint: `${SITE_URL}/api/mcp`,
  serverInfo: {
    name: "pezeex-shopping-assistant",
    title: "Pezeex Shopping Assistant",
    version: "1.0.0",
    description:
      "AI-powered shopping assistant that discovers similar, lower-priced product alternatives across trusted global and regional online stores.",
    websiteUrl: SITE_URL,
  },
  transport: {
    type: "streamable-http",
    endpoint: `${SITE_URL}/api/mcp`,
  },
  remotes: [
    {
      type: "streamable-http",
      url: `${SITE_URL}/api/mcp`,
    },
  ],
  capabilities: {
    tools: {
      listChanged: false,
    },
    resources: {
      subscribe: false,
      listChanged: false,
    },
    prompts: {
      listChanged: false,
    },
  },
  authentication: {
    required: false,
  },
  tools: [
    {
      name: "search_product_alternatives",
      description:
        "Find similar, lower-priced product alternatives across trusted online stores by product name or product URL.",
      inputSchema: {
        type: "object",
        properties: {
          query: {
            type: "string",
            description: "Product name, model, or product URL to find cheaper alternatives for.",
          },
          country: {
            type: "string",
            description: "Two-letter ISO country code (e.g., US, SA, AE, GB, DE). Defaults to US.",
          },
          language: {
            type: "string",
            description: "Preferred response language (e.g., English, العربية). Defaults to English.",
          },
        },
        required: ["query"],
      },
    },
    {
      name: "get_supported_countries",
      description:
        "Return the list of supported shopping countries, currencies, and popular retailers available on Pezeex.",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ],
  resources: [
    {
      uri: `${SITE_URL}/llms.txt`,
      name: "Pezeex LLMs Guide",
      description: "Structured directory of Pezeex pages and machine-readable endpoints.",
      mimeType: "text/plain",
    },
  ],
};

export function resolveKnownPageRoute(pathname: string): PageRouteKey | null {
  const normalized = (pathname || "/").toLowerCase().replace(/\/+$/, "") || "/";
  if (normalized === "/" || normalized === "/index.html") return "home";
  if (normalized === "/about") return "about";
  if (normalized === "/contact") return "contact";
  if (normalized === "/privacy" || normalized === "/privacy-policy") return "privacy";
  if (normalized === "/terms" || normalized === "/terms-of-use") return "terms";
  return null;
}

export function resolveMarkdownFileRoute(pathname: string): PageRouteKey | null {
  const normalized = (pathname || "").toLowerCase();
  if (normalized === "/index.md") return "home";
  if (normalized === "/about.md") return "about";
  if (normalized === "/contact.md") return "contact";
  if (normalized === "/privacy-policy.md" || normalized === "/privacy.md") return "privacy";
  if (normalized === "/terms-of-use.md" || normalized === "/terms.md") return "terms";
  return null;
}

/**
 * Determine whether the HTTP Accept header explicitly prefers text/markdown over text/html.
 */
export function prefersMarkdown(acceptHeader?: string): boolean {
  if (!acceptHeader || typeof acceptHeader !== "string") return false;
  const ranges = acceptHeader
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);

  let mdQ = -1;
  let htmlQ = -1;

  for (const range of ranges) {
    const [rawType, ...params] = range.split(";").map((s) => s.trim().toLowerCase());
    let q = 1;
    for (const p of params) {
      if (p.startsWith("q=")) {
        const parsed = parseFloat(p.slice(2));
        if (!Number.isNaN(parsed)) q = parsed;
      }
    }
    if (rawType === "text/markdown" || rawType === "text/x-markdown") {
      mdQ = Math.max(mdQ, q);
    } else if (rawType === "text/html" || rawType === "application/xhtml+xml") {
      htmlQ = Math.max(htmlQ, q);
    }
  }

  return mdQ > 0 && mdQ >= htmlQ;
}

export function getLinkHeader(routeKey: PageRouteKey): string {
  const meta = PAGE_METADATA[routeKey];
  return [
    `<${SITE_URL}/llms.txt>; rel="describedby"; type="text/plain"`,
    `<${SITE_URL}${meta.markdownPath}>; rel="alternate"; type="text/markdown"`,
    `<${SITE_URL}/.well-known/mcp/server-card.json>; rel="service-desc"; type="application/json"`,
    `<${SITE_URL}/sitemap.xml>; rel="sitemap"; type="application/xml"`,
  ].join(", ");
}

export function getPageMarkdown(routeKey: PageRouteKey): string {
  switch (routeKey) {
    case "about":
      return `# About Pezeex

> Pezeex is an AI-powered shopping assistant designed to help consumers avoid overpaying by discovering similar, lower-priced product alternatives across online stores.

## Our Mission

Online prices vary widely across brands and retailers for products with nearly identical specifications and quality. Pezeex analyzes any product name or product link you provide and surfaces comparable, more affordable alternatives from reputable merchants in your region.

## Key Capabilities

- **Product Name & URL Analysis:** Search by product title, model number, or paste a direct product page link.
- **Localized Store Matching:** Supports 25+ countries across the Middle East, North America, Europe, and Asia-Pacific with local currencies and popular regional stores.
- **Multilingual Interface:** Available in 37 languages including English and Arabic.
- **Free Daily Searches:** Up to 25 searches per day at no cost to users.

## Affiliate Transparency

Pezeex is free to use. We may earn a small affiliate commission when you click an offer or complete a purchase through a partner link, at no extra cost to you. Always verify final prices, shipping costs, and seller terms on the merchant website before purchasing.

## Links

- [Home](${SITE_URL}/)
- [Contact Us](${SITE_URL}/contact)
- [Privacy Policy](${SITE_URL}/privacy-policy)
- [Terms of Use](${SITE_URL}/terms-of-use)
- Email: [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL})
`;

    case "contact":
      return `# Contact Pezeex

> Reach the Pezeex team for support, partnerships, privacy inquiries, or feedback.

## Direct Email

- **General, Support & Legal Inquiries:** [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL})

## Official Social Profiles

- **Instagram:** [@itti_fc4321](https://www.instagram.com/itti_fc4321)
- **Reddit:** [u/ExternalAd2358](https://www.reddit.com/user/ExternalAd2358)
- **Support Pezeex:** [PayPal](https://paypal.me/AbdullahAlbukhari37)

## Related Pages

- [Home](${SITE_URL}/)
- [About Pezeex](${SITE_URL}/about)
- [Privacy Policy](${SITE_URL}/privacy-policy)
- [Terms of Use](${SITE_URL}/terms-of-use)
`;

    case "privacy":
      return `# Privacy Policy — Pezeex

**Effective Date:** 24/11/2026  
**Domain:** ${SITE_URL}

Pezeex ("we", "us", or "our") is committed to protecting your privacy. This Privacy Policy explains how we collect, use, and safeguard your information when you use pezeex.com.

## 1. What Information We Collect

- **Search Queries & Product Links:** Product names, descriptions, or URLs submitted so our AI can suggest similar, lower-priced alternatives.
- **Technical & Location Data:** IP address (for approximate country detection), browser type, device information, and cookie data.
- **Usage & Local Storage Data:** Pages visited, click activity on product suggestions or affiliate links, and browser localStorage preferences (language, theme, daily search counter).
- **Direct Communications:** Your email address and message content if you contact us directly.

## 2. How We Use Your Information

- Process product queries using AI to suggest affordable alternatives and deals.
- Tailor store suggestions to your approximate country and remember language and display preferences.
- Enforce daily fair-usage limits (25 searches/day) and protect service stability.
- Measure traffic, attribute affiliate referrals, and improve the Service.

## 3. Sharing Your Information

We may share limited data with AI service providers, affiliate networks (e.g., ConvertLink, Mitgo, Takeads), analytics providers (Google Tag Manager / Analytics), and IP geolocation services (GeoJS). We do not sell your personal information.

## 4. Cookies & Local Storage

You can manage your cookie preferences via your browser or on [pezeex.com/privacy-policy](${SITE_URL}/privacy-policy).

## 5. Your Privacy Rights

Users in the EU, UK, Switzerland (GDPR/FADP), United States (CCPA/CPRA), Canada (PIPEDA), and Latin America (LGPD) may exercise rights to access, correct, delete, or restrict processing of their data.

## 6. Contact Us

For privacy questions or data requests, email [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL}).
`;

    case "terms":
      return `# Terms of Use — Pezeex

**Effective Date:** 24/11/2026  
**Domain:** ${SITE_URL}

Welcome to Pezeex. These Terms of Use govern your access to and use of pezeex.com, an AI-powered shopping assistant that helps users discover similar, lower-priced product alternatives across third-party online stores.

## 1. Acceptance of Terms

By accessing or using pezeex.com, you agree to these Terms.

## 2. Service Description

Pezeex uses artificial intelligence to analyze product names or links you submit and recommend similar, more affordable product alternatives and offers from third-party merchants and affiliate networks.

## 3. Accuracy of Information

AI-generated product suggestions, prices, and offers may occasionally be inaccurate or change without notice. Always verify prices, shipping terms, and availability directly with the merchant before purchasing.

## 4. User Conduct

You agree not to abuse, disrupt, overload, or bypass daily fair-usage limits on the Service, or submit unlawful or harmful content.

## 5. Intellectual Property

All branding, logos, and original content on Pezeex are owned by Pezeex or its licensors.

## 6. Affiliate Disclosure

We may earn a commission if you click on an offer or complete a purchase through an affiliate link, at no extra cost to you.

## 7. Disclaimer of Liability & Consumer Rights

Use of third-party merchant websites is at your own risk. Nothing in these Terms limits mandatory consumer protection rights under applicable laws in your jurisdiction.

## 8. Contact Us

For legal queries or feedback, email [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL}).
`;

    case "home":
    default:
      return `# Pezeex — AI Shopping Assistant for Cheaper Product Alternatives

> Don't pay more than you should. Pezeex uses AI to help you find similar, lower-priced alternatives to the products you love across trusted global and local online stores.

- **Website:** ${SITE_URL}/
- **Contact:** [${CONTACT_EMAIL}](mailto:${CONTACT_EMAIL})
- **Pricing:** Free (up to 25 AI product searches per day)

## How Pezeex Works

1. **Enter a product name or paste a product URL** from any online retailer.
2. **AI analyzes specifications and pricing** to identify comparable, more affordable alternatives.
3. **Compare localized offers** across trusted stores tailored to your country and currency (25+ countries and 37 languages supported).

## Key Pages

- [About Pezeex](${SITE_URL}/about)
- [Contact Us](${SITE_URL}/contact)
- [Privacy Policy](${SITE_URL}/privacy-policy)
- [Terms of Use](${SITE_URL}/terms-of-use)

## Agent Resources

- [llms.txt](${SITE_URL}/llms.txt)
- [MCP Server Card](${SITE_URL}/.well-known/mcp/server-card.json)
- [MCP Endpoint](${SITE_URL}/api/mcp)
- [Sitemap](${SITE_URL}/sitemap.xml)
`;
  }
}

export function getPageJsonLd(routeKey: PageRouteKey): Record<string, unknown> {
  const meta = PAGE_METADATA[routeKey];
  const graph: Record<string, unknown>[] = [
    {
      "@type": "Organization",
      "@id": `${SITE_URL}/#org`,
      name: SITE_NAME,
      url: SITE_URL,
      logo: `${SITE_URL}/icon-512.png`,
      description: "AI shopping assistant for finding similar, lower-priced product alternatives across online stores.",
      email: CONTACT_EMAIL,
      contactPoint: {
        "@type": "ContactPoint",
        contactType: "customer support",
        email: CONTACT_EMAIL,
        url: `${SITE_URL}/contact`,
      },
      sameAs: SAME_AS_PROFILES,
    },
    {
      "@type": "WebSite",
      "@id": `${SITE_URL}/#site`,
      name: SITE_NAME,
      url: SITE_URL,
      publisher: { "@id": `${SITE_URL}/#org` },
      potentialAction: {
        "@type": "SearchAction",
        target: `${SITE_URL}/?q={search_term_string}`,
        "query-input": "required name=search_term_string",
      },
    },
    {
      "@type": "WebApplication",
      "@id": `${SITE_URL}/#app`,
      name: "Pezeex Shopping Assistant",
      url: SITE_URL,
      applicationCategory: "ShoppingApplication",
      operatingSystem: "All",
      publisher: { "@id": `${SITE_URL}/#org` },
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    },
    {
      "@type": routeKey === "about" ? "AboutPage" : routeKey === "contact" ? "ContactPage" : "WebPage",
      "@id": `${meta.canonicalUrl}#page`,
      url: meta.canonicalUrl,
      name: meta.title,
      description: meta.description,
      isPartOf: { "@id": `${SITE_URL}/#site` },
      about: { "@id": `${SITE_URL}/#org` },
    },
  ];

  if (routeKey === "home") {
    graph.push({
      "@type": "FAQPage",
      "@id": `${SITE_URL}/#faq`,
      mainEntity: [
        {
          "@type": "Question",
          name: "How does Pezeex work?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Enter any product name or paste a store URL and Pezeex uses AI to recommend similar, lower-priced alternatives in your country.",
          },
        },
        {
          "@type": "Question",
          name: "Is Pezeex free?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes, Pezeex is free and includes up to 25 AI searches per day across 25+ countries and 37 languages.",
          },
        },
      ],
    });
  }

  return {
    "@context": "https://schema.org",
    "@graph": graph,
  };
}

export function getPageSsrHtml(routeKey: PageRouteKey): string {
  const sharedNav = `<header class="ssr-fallback"><nav aria-label="Primary"><a href="/">Pezeex</a> | <a href="/about">About</a> | <a href="/contact">Contact</a> | <a href="/privacy-policy">Privacy Policy</a> | <a href="/terms-of-use">Terms of Use</a></nav></header>`;

  const sharedFooter = `<footer class="ssr-fallback"><p>Contact: <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></p><nav aria-label="Footer"><a href="/about">About Pezeex</a> | <a href="/contact">Contact Us</a> | <a href="/privacy-policy">Privacy Policy</a> | <a href="/terms-of-use">Terms of Use</a> | <a href="/llms.txt">llms.txt</a> | <a href="https://www.instagram.com/itti_fc4321" rel="noopener noreferrer">Instagram</a> | <a href="https://www.reddit.com/user/ExternalAd2358" rel="noopener noreferrer">Reddit</a></nav></footer>`;

  if (routeKey === "about") {
    return `${sharedNav}<main class="ssr-fallback"><h1>About Pezeex</h1><p>Pezeex is an AI-powered shopping assistant built to help everyday shoppers avoid overpaying. By analyzing product names, model numbers, and store links, Pezeex identifies comparable, lower-priced alternatives across reputable global and regional online retailers.</p><h2>How Pezeex Works</h2><p>Online prices often vary significantly across brands and merchants for items with similar materials, specifications, and everyday performance. Enter any product name or paste a product URL into Pezeex, and our assistant searches for similar, more affordable alternatives tailored to your local country and currency.</p><h2>Supported Countries &amp; Languages</h2><p>Pezeex supports shoppers in more than 25 countries across the Middle East, North America, Europe, and Asia-Pacific—including the United States, Saudi Arabia, UAE, United Kingdom, Canada, Germany, France, Spain, Italy, Netherlands, Egypt, Kuwait, Qatar, Turkey, India, Japan, Australia, and Brazil—with an interface localized into 37 languages.</p><h2>Free Access &amp; Affiliate Transparency</h2><p>Pezeex is free to use with up to 25 AI product searches per day. We may earn a small affiliate commission if you click an offer or make a purchase through a partner link, at zero additional cost to you. Always verify final prices, shipping fees, and seller policies directly on the retailer website before buying.</p></main>${sharedFooter}`;
  }

  if (routeKey === "contact") {
    return `${sharedNav}<main class="ssr-fallback"><h1>Contact Pezeex</h1><p>Reach the Pezeex team for customer support, retailer or affiliate partnerships, privacy requests, press inquiries, or general product feedback.</p><h2>Direct Email</h2><p>Email our team directly at <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>. We respond to support, legal, and data privacy inquiries sent to this address.</p><h2>Official Social &amp; Community Profiles</h2><ul><li>Instagram: <a href="https://www.instagram.com/itti_fc4321" rel="noopener noreferrer">@itti_fc4321</a></li><li>Reddit: <a href="https://www.reddit.com/user/ExternalAd2358" rel="noopener noreferrer">u/ExternalAd2358</a></li><li>Support Pezeex: <a href="https://paypal.me/AbdullahAlbukhari37" rel="noopener noreferrer">PayPal</a></li></ul></main>${sharedFooter}`;
  }

  if (routeKey === "privacy") {
    return `${sharedNav}<main class="ssr-fallback"><h1>Privacy Policy</h1><p>Effective Date: 24/11/2026. Pezeex (pezeex.com) is committed to protecting your privacy when you use our AI-powered shopping assistant.</p><h2>What Information We Collect</h2><p>We process search queries and product links you submit to recommend cheaper alternatives, approximate country derived from IP address to show relevant regional stores, usage and browser localStorage preferences (language, theme, and daily search counter), and direct email communications.</p><h2>Your Privacy Rights</h2><p>We do not sell personal information. Depending on your region—including the EU, UK, and Switzerland (GDPR and FADP), the United States (CCPA/CPRA), Canada (PIPEDA), and Latin America (LGPD)—you may request access, correction, restriction, or deletion of personal data.</p><h2>Privacy Contact</h2><p>Send privacy questions or data requests to <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.</p></main>${sharedFooter}`;
  }

  if (routeKey === "terms") {
    return `${sharedNav}<main class="ssr-fallback"><h1>Terms of Use</h1><p>Effective Date: 24/11/2026. These Terms govern your access to and use of Pezeex (pezeex.com), an AI-powered shopping assistant.</p><h2>Service Description &amp; Accuracy</h2><p>Pezeex analyzes product names or URLs you submit and suggests similar, lower-priced alternatives across third-party online stores. Because merchant pricing and stock change frequently, AI-generated prices and recommendations may occasionally be inaccurate. Always confirm prices, shipping terms, and availability directly with the merchant before purchasing.</p><h2>Affiliate Disclosure &amp; Consumer Rights</h2><p>Pezeex may earn a commission when you click an offer or complete a purchase through an affiliate link at no extra cost to you. Nothing in these Terms limits mandatory consumer protection rights under applicable laws in your jurisdiction.</p><h2>Legal Contact</h2><p>Send legal questions or feedback to <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.</p></main>${sharedFooter}`;
  }

  return `${sharedNav}<main class="ssr-fallback"><h1>Pezeex — AI Shopping Assistant for Cheaper Product Alternatives</h1><p>Don't pay more than you should. Pezeex is a free AI-powered shopping assistant that helps you find similar, lower-priced alternatives to the products you love across trusted global and regional online stores.</p><form action="/" method="get" toolname="search_product_alternatives" tooldescription="Search Pezeex for similar, lower-priced product alternatives across trusted online stores by product name or product URL."><label for="pezeex-search-input">Product name or URL</label><input id="pezeex-search-input" name="q" type="search" placeholder="Type a product name or paste a link..." required /><button type="submit">Search Alternatives</button></form><h2>How Pezeex Helps You Save Money</h2><p>Enter any product name, brand model, or direct product link from an online store. Pezeex analyzes the item's category and key features, then recommends comparable, more affordable alternatives from reputable merchants tailored to your location and currency.</p><ul><li>Search by product name, model number, or store link in seconds.</li><li>Localized store matching across 25+ countries including the United States, Saudi Arabia, UAE, United Kingdom, Canada, Germany, France, Spain, Italy, Netherlands, Egypt, Kuwait, Qatar, Turkey, India, Japan, Australia, and Brazil.</li><li>Available in 37 languages including English, Arabic, Spanish, French, German, Japanese, and Hindi.</li><li>Free to use with up to 25 AI-powered product searches every day.</li></ul><h2>Frequently Asked Questions</h2><h3>How does Pezeex find cheaper alternatives?</h3><p>Pezeex compares the product name or link you submit against similar options offered by trusted regional and international online retailers, highlighting lower-priced alternatives with comparable specifications.</p><h3>Is Pezeex free to use?</h3><p>Yes. Pezeex is completely free with up to 25 searches per day. We may earn a small affiliate commission on qualifying clicks or purchases at no extra cost to you. Always verify final prices and shipping terms on the merchant website.</p><h2>Agent &amp; Machine-Readable Access</h2><p>AI agents can inspect <a href="/llms.txt">llms.txt</a>, request Markdown via <code>Accept: text/markdown</code>, or discover tools through our <a href="/.well-known/mcp/server-card.json">MCP Server Card</a>.</p></main>${sharedFooter}`;
}

function escapeHtmlAttr(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function serializeJsonLd(data: Record<string, unknown>): string {
  return JSON.stringify(data).replace(/</g, "\\u003c");
}

export function applyPageTemplate(baseHtml: string, routeKey: PageRouteKey): string {
  const meta = PAGE_METADATA[routeKey];
  const jsonLd = serializeJsonLd(getPageJsonLd(routeKey));
  const ssrBody = getPageSsrHtml(routeKey);

  let html = baseHtml;

  html = html.replace(/<title>[\s\S]*?<\/title>/i, `<title>${escapeHtmlAttr(meta.title)}</title>`);
  html = html.replace(
    /<meta\s+name="description"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="description" content="${escapeHtmlAttr(meta.description)}" />`
  );
  html = html.replace(
    /<link\s+rel="canonical"\s+href="[^"]*"\s*\/?>/i,
    `<link rel="canonical" href="${escapeHtmlAttr(meta.canonicalUrl)}" />`
  );
  html = html.replace(
    /<meta\s+property="og:title"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:title" content="${escapeHtmlAttr(meta.title)}" />`
  );
  html = html.replace(
    /<meta\s+property="og:description"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:description" content="${escapeHtmlAttr(meta.description)}" />`
  );
  html = html.replace(
    /<meta\s+property="og:url"\s+content="[^"]*"\s*\/?>/i,
    `<meta property="og:url" content="${escapeHtmlAttr(meta.canonicalUrl)}" />`
  );
  html = html.replace(
    /<meta\s+name="twitter:title"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="twitter:title" content="${escapeHtmlAttr(meta.title)}" />`
  );
  html = html.replace(
    /<meta\s+name="twitter:description"\s+content="[^"]*"\s*\/?>/i,
    `<meta name="twitter:description" content="${escapeHtmlAttr(meta.description)}" />`
  );
  html = html.replace(
    /<link\s+rel="alternate"\s+type="text\/markdown"\s+href="[^"]*"\s*\/?>/i,
    `<link rel="alternate" type="text/markdown" href="${escapeHtmlAttr(`${SITE_URL}${meta.markdownPath}`)}" />`
  );
  html = html.replace(
    /<script\s+type="application\/ld\+json"[^>]*>[\s\S]*?<\/script>/i,
    `<script type="application/ld+json">${jsonLd}</script>`
  );
  html = html.replace(
    /<div\s+id="root">[\s\S]*?<\/div>/i,
    `<div id="root">${ssrBody}</div>`
  );

  return html;
}

export function get404Html(requestedPath: string): string {
  const safePath = escapeHtmlAttr(requestedPath.slice(0, 160));
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta name="robots" content="noindex, follow" />
    <title>404 — Page Not Found | Pezeex</title>
    <meta name="description" content="The requested page could not be found on Pezeex." />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg?v=3" />
  </head>
  <body>
    <main>
      <h1>404 — Page Not Found</h1>
      <p>The requested URL (<code>${safePath}</code>) does not exist on Pezeex.</p>
      <nav aria-label="Main navigation">
        <a href="/">Home</a> |
        <a href="/about">About Pezeex</a> |
        <a href="/contact">Contact Us</a> |
        <a href="/privacy-policy">Privacy Policy</a> |
        <a href="/terms-of-use">Terms of Use</a>
      </nav>
      <p>Need help? Contact <a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a>.</p>
    </main>
  </body>
</html>`;
}

export function get404Markdown(requestedPath: string): string {
  const safePath = requestedPath.replace(/[\r\n]/g, "").slice(0, 160);
  return `# 404 — Page Not Found

The requested URL \`${safePath}\` does not exist on Pezeex.

## Available Pages

- [Home](${SITE_URL}/)
- [About Pezeex](${SITE_URL}/about)
- [Contact Us](${SITE_URL}/contact)
- [Privacy Policy](${SITE_URL}/privacy-policy)
- [Terms of Use](${SITE_URL}/terms-of-use)
- [llms.txt](${SITE_URL}/llms.txt)
`;
}
