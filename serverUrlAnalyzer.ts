import dns from "dns";
import net from "net";

export interface AnalyzedProductLink {
  originalUrl: string;
  finalUrl: string;
  storeDomain: string;
  storeName: string;
  title: string;
  brand: string;
  price: string;
  description: string;
  category: string;
  productId: string;
  urlSlugKeywords: string;
  countryHint: string;
  surroundingText: string;
  fetchedFromPage: boolean;
  blockedUnsafeUrl?: boolean;
}

const MAX_REDIRECT_HOPS = 4;
const FETCH_TIMEOUT_MS = 4500;
const DNS_TIMEOUT_MS = 2000;
const MAX_HTML_BYTES = 160 * 1024; // 160KB cap covers <head>, OG tags, and JSON-LD safely

const BLOCKED_BOT_TITLE_PATTERNS: RegExp[] = [
  /robot\s*check/i,
  /just\s+a\s+moment/i,
  /access\s+denied/i,
  /attention\s+required/i,
  /are\s+you\s+a\s+human/i,
  /verify\s+you\s+are\s+human/i,
  /security\s+check/i,
  /captcha/i,
  /cloudflare/i,
  /page\s+not\s+found/i,
  /sorry!\s*something\s+went\s+wrong/i,
  /enable\s+javascript/i,
  /\b403\b|\b404\b|\b503\b/,
  /^(amazon(\.[a-z.]+)?|noon|shein|temu|aliexpress|ebay|walmart|target|jarir|extra|ikea|carrefour)$/i,
];

const URL_NOISE_SEGMENTS = new Set([
  "dp",
  "gp",
  "product",
  "products",
  "item",
  "items",
  "p",
  "pd",
  "pr",
  "s",
  "c",
  "en",
  "ar",
  "fr",
  "de",
  "es",
  "it",
  "nl",
  "tr",
  "us",
  "uk",
  "gb",
  "sa",
  "ae",
  "eg",
  "kw",
  "qa",
  "bh",
  "om",
  "jo",
  "sa-ar",
  "sa-en",
  "ae-ar",
  "ae-en",
  "saudi-ar",
  "saudi-en",
  "uae-ar",
  "uae-en",
  "egypt-ar",
  "egypt-en",
  "ar-sa",
  "en-sa",
  "ar-ae",
  "en-ae",
  "shop",
  "store",
  "buy",
  "catalog",
  "detail",
  "details",
  "index",
  "html",
  "htm",
  "ref",
  "d",
  "t",
  "h5",
  "sharejump",
  "goods",
  "wholesale",
  "mafsau",
  "mafuae",
  "mafegy",
]);

function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split(".").map((n) => Number.parseInt(n, 10));
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b, c] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8 (RFC1918)
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 (CGNAT)
  if (a === 127) return true; // 127.0.0.0/8 (Loopback)
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 (Link-local / Cloud Metadata)
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 (RFC1918)
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24
  if (a === 192 && b === 0 && c === 2) return true; // 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 (RFC1918)
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 (TEST-NET-2)
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 (TEST-NET-3)
  if (a >= 224) return true; // 224.0.0.0/4 Multicast & 240.0.0.0/4 Reserved
  return false;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  const clean = (ip || "").trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  if (!clean) return true;

  if (net.isIPv4(clean)) {
    return isPrivateOrReservedIPv4(clean);
  }

  if (net.isIPv6(clean)) {
    if (clean === "::" || clean === "::1") return true;

    // IPv4-mapped IPv6 dotted form: ::ffff:127.0.0.1
    const v4MappedDotted = clean.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (v4MappedDotted) {
      return isPrivateOrReservedIPv4(v4MappedDotted[1]);
    }

    // IPv4-mapped IPv6 hex form: ::ffff:7f00:0001
    const v4MappedHex = clean.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
    if (v4MappedHex) {
      const hi = Number.parseInt(v4MappedHex[1], 16);
      const lo = Number.parseInt(v4MappedHex[2], 16);
      const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateOrReservedIPv4(ipv4);
    }

    // Unique local (fc00::/7), link-local (fe80::/10), multicast (ff00::/8), documentation (2001:db8::/32)
    const firstHextetMatch = clean.match(/^([0-9a-f]{1,4}):/i);
    if (firstHextetMatch) {
      const first = Number.parseInt(firstHextetMatch[1], 16);
      if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7
      if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10
      if ((first & 0xff00) === 0xff00) return true; // ff00::/8
      if (clean.startsWith("2001:db8:") || clean.startsWith("2001:0db8:")) return true;
    }

    // Unspecified / loopback / IPv4-compatible forms starting with "::"
    if (clean.startsWith("::")) return true;
    return false;
  }

  return true;
}

export function isPrivateOrInternalHost(hostname: string): boolean {
  const h = (hostname || "").toLowerCase().trim().replace(/^\[|\]$/g, "").replace(/\.+$/, "");
  if (!h || h.length > 253) return true;

  if (
    h === "localhost" ||
    h === "metadata" ||
    h === "metadata.google.internal" ||
    h === "instance-data" ||
    h === "::1" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".lan") ||
    h.endsWith(".home") ||
    h.endsWith(".arpa") ||
    h.endsWith(".corp") ||
    h.endsWith(".intranet")
  ) {
    return true;
  }

  // Block raw IPv4, IPv6, decimal integer IPs (e.g. 2130706433), hex/octal IP obfuscations
  if (net.isIP(h) !== 0 || h.includes(":")) return true;
  if (/^\d+$/.test(h) || /^0x[0-9a-f]+$/i.test(h)) return true;
  const labels = h.split(".");
  if (labels.every((lbl) => /^(?:\d+|0x[0-9a-f]+)$/i.test(lbl))) {
    return true;
  }
  if (!h.includes(".")) return true;

  return false;
}

export async function validatePublicUrlWithDns(
  urlString: string,
  allowHttp: boolean = true
): Promise<URL | null> {
  try {
    if (!urlString || typeof urlString !== "string" || urlString.length > 2048) return null;
    if (/[\u0000-\u001F\u007F\s]/.test(urlString.trim())) return null;

    const parsed = new URL(urlString.trim());
    if (allowHttp) {
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    } else {
      if (parsed.protocol !== "https:") return null;
    }
    if (parsed.username || parsed.password) return null;
    if (
      parsed.port &&
      parsed.port !== "443" &&
      !(allowHttp && parsed.protocol === "http:" && parsed.port === "80")
    ) {
      return null;
    }
    if (isPrivateOrInternalHost(parsed.hostname)) return null;

    // Resolve all DNS records and verify every IP is strictly public (prevents DNS rebinding / internal routing)
    let lookupTimer: NodeJS.Timeout | undefined;
    const records = await Promise.race([
      dns.promises.lookup(parsed.hostname, { all: true, verbatim: true }),
      new Promise<never>((_, reject) => {
        lookupTimer = setTimeout(() => reject(new Error("DNS timeout")), DNS_TIMEOUT_MS);
      }),
    ]).finally(() => {
      if (lookupTimer) clearTimeout(lookupTimer);
    });

    if (!Array.isArray(records) || records.length === 0) return null;
    for (const rec of records) {
      if (!rec?.address || isPrivateOrReservedIp(rec.address)) {
        return null;
      }
    }
    return parsed;
  } catch {
    return null;
  }
}

function decodeHtmlEntities(input: string): string {
  if (!input) return "";
  return input
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#x([0-9a-f]{1,6});/gi, (_, hex) => {
      const code = Number.parseInt(hex, 16);
      return Number.isFinite(code) && code >= 32 && code <= 0x10ffff ? String.fromCodePoint(code) : " ";
    })
    .replace(/&#(\d{1,7});/g, (_, dec) => {
      const code = Number.parseInt(dec, 10);
      return Number.isFinite(code) && code >= 32 && code <= 0x10ffff ? String.fromCodePoint(code) : " ";
    });
}

function sanitizeExtractedText(raw: unknown, maxLen: number): string {
  if (typeof raw !== "string" && typeof raw !== "number") return "";
  return decodeHtmlEntities(String(raw))
    .replace(/<[^>]*>/g, " ")
    .replace(/[\u0000-\u001F\u007F"`<>\\]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
}

function isUsefulProductTitle(title: string): boolean {
  const t = (title || "").trim();
  if (t.length < 4) return false;
  return !BLOCKED_BOT_TITLE_PATTERNS.some((re) => re.test(t));
}

function detectCountryHintFromUrl(urlObj: URL): string {
  const host = urlObj.hostname.toLowerCase().replace(/^www\./, "");
  const pathLower = urlObj.pathname.toLowerCase();

  if (host.endsWith(".sa") || host.includes("jarir.") || host.includes("extra.com") || host.includes("niceonesa") || host.includes("carrefourksa")) return "SA";
  if (host.endsWith(".ae") || host.includes("carrefouruae")) return "AE";
  if (host.endsWith(".eg") || host.includes("carrefouregypt")) return "EG";
  if (host.endsWith(".co.uk") || host.endsWith(".uk")) return "GB";
  if (host.endsWith(".de")) return "DE";
  if (host.endsWith(".fr")) return "FR";
  if (host.endsWith(".es")) return "ES";
  if (host.endsWith(".it")) return "IT";
  if (host.endsWith(".nl")) return "NL";
  if (host.endsWith(".ca")) return "CA";
  if (host.endsWith(".com.tr") || host.includes("trendyol.") || host.includes("hepsiburada.")) return "TR";
  if (host.endsWith(".in") || host.includes("flipkart.")) return "IN";
  if (host.endsWith(".co.jp")) return "JP";
  if (host.endsWith(".com.au")) return "AU";
  if (host.endsWith(".com.br") || host.includes("mercadolivre.")) return "BR";
  if (host.includes("xcite.")) return "KW";
  if (host.includes("smartbuy.jo")) return "JO";

  if (host.includes("noon.com")) {
    if (pathLower.includes("/saudi-")) return "SA";
    if (pathLower.includes("/uae-")) return "AE";
    if (pathLower.includes("/egypt-")) return "EG";
  }
  if (host.includes("ikea.com")) {
    const m = pathLower.match(/^\/([a-z]{2})\//);
    if (m) return m[1].toUpperCase();
  }
  return "";
}

function deriveStoreNameFromHost(hostname: string): string {
  const clean = hostname.toLowerCase().replace(/^(www|m|ar|en|us|uk|sa|ae|fr|de|es|it|shop|store)\./i, "");
  const parts = clean.split(".");
  if (parts.length >= 2) {
    const base = parts[0];
    return base.charAt(0).toUpperCase() + base.slice(1);
  }
  return clean;
}

function extractSlugAndIdFromUrl(urlObj: URL): { slugKeywords: string; productId: string } {
  const fullPath = urlObj.pathname || "";
  let productId = "";

  // Extract common product identifiers (Amazon ASIN, Noon SKU, AliExpress/eBay item ID)
  const asinMatch = fullPath.match(/(?:\/dp\/|\/gp\/product\/|\/product\/)([A-Z0-9]{10})(?:\/|$|\?)/i);
  if (asinMatch) {
    productId = asinMatch[1].toUpperCase();
  } else {
    const noonMatch = fullPath.match(/\/(N[A-Z0-9]{6,14})\/p(?:\/|$)/i);
    if (noonMatch) productId = noonMatch[1].toUpperCase();
  }

  const candidateChunks: string[] = [];
  const rawSegments = fullPath.split("/").filter(Boolean);

  for (const rawSeg of rawSegments) {
    let seg = rawSeg;
    try {
      seg = decodeURIComponent(rawSeg);
    } catch {
      // keep rawSeg if malformed percent-encoding
    }
    seg = seg.replace(/\.(html?|php|aspx?)$/i, "").trim();
    if (!seg || seg.length < 3) continue;
    const lower = seg.toLowerCase();
    if (URL_NOISE_SEGMENTS.has(lower)) continue;
    // Skip pure IDs / ASINs / UUIDs / opaque tracking codes
    if (/^[0-9]+$/.test(seg)) continue;
    if (/^[a-f0-9-]{20,}$/i.test(seg)) continue;
    if (/^[A-Z0-9]{8,14}$/.test(seg) && /\d/.test(seg)) continue;
    if (productId && seg.toUpperCase() === productId) continue;

    // Remove trailing product code suffixes (e.g., "-p-12345678", "-70261150")
    const cleaned = seg
      .replace(/[-_]+p[-_]*\d{5,}$/i, "")
      .replace(/[-_]+\d{6,}$/i, "")
      .replace(/[-_+]+/g, " ")
      .replace(/\s+/g, " ")
      .trim();

    if (cleaned.length >= 4 && /[a-z\u0600-\u06FF]{3,}/i.test(cleaned)) {
      candidateChunks.push(cleaned);
    }
  }

  // Also check human-readable query parameters if path had little info
  if (candidateChunks.length === 0) {
    for (const paramKey of ["k", "q", "query", "keyword", "keywords", "search", "search_key", "SearchText", "title", "name", "goods_name"]) {
      const val = urlObj.searchParams.get(paramKey);
      if (val && val.trim().length >= 3) {
        candidateChunks.push(val.trim());
        break;
      }
    }
  }

  // Pick the most descriptive slug segment(s)
  candidateChunks.sort((a, b) => b.length - a.length);
  const slugKeywords = sanitizeExtractedText(candidateChunks.slice(0, 2).join(" "), 160);
  return { slugKeywords, productId };
}

function extractMetaContent(html: string, attrName: string, attrValue: string): string {
  const escapedVal = attrValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const patterns = [
    new RegExp(`<meta\\b[^>]*\\b${attrName}\\s*=\\s*["']${escapedVal}["'][^>]*\\bcontent\\s*=\\s*["']([^"']{1,500})["'][^>]*>`, "i"),
    new RegExp(`<meta\\b[^>]*\\bcontent\\s*=\\s*["']([^"']{1,500})["'][^>]*\\b${attrName}\\s*=\\s*["']${escapedVal}["'][^>]*>`, "i"),
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m && m[1]) {
      return sanitizeExtractedText(m[1], 240);
    }
  }
  return "";
}

function findProductJsonLd(node: any): any | null {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const item of node) {
      const found = findProductJsonLd(item);
      if (found) return found;
    }
    return null;
  }
  const typeVal = node["@type"];
  const isProduct =
    (typeof typeVal === "string" && typeVal.toLowerCase().includes("product")) ||
    (Array.isArray(typeVal) && typeVal.some((t) => typeof t === "string" && t.toLowerCase().includes("product")));
  if (isProduct && typeof node.name === "string" && node.name.trim()) {
    return node;
  }
  if (Array.isArray(node["@graph"])) {
    return findProductJsonLd(node["@graph"]);
  }
  return null;
}

function extractMetadataFromHtml(html: string): {
  title: string;
  brand: string;
  price: string;
  description: string;
  category: string;
  siteName: string;
  canonicalUrl: string;
} {
  let title = "";
  let brand = "";
  let price = "";
  let description = "";
  let category = "";
  let siteName = "";
  let canonicalUrl = "";

  // 1. JSON-LD Product structured data (highest precision on e-commerce sites)
  const ldRegex = /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>([\s\S]{10,45000}?)<\/script>/gi;
  let ldMatch: RegExpExecArray | null;
  while ((ldMatch = ldRegex.exec(html)) !== null) {
    try {
      const parsed = JSON.parse(ldMatch[1].trim());
      const prod = findProductJsonLd(parsed);
      if (prod) {
        if (!title && typeof prod.name === "string") {
          const cand = sanitizeExtractedText(prod.name, 160);
          if (isUsefulProductTitle(cand)) title = cand;
        }
        if (!brand) {
          const b = typeof prod.brand === "string" ? prod.brand : prod.brand?.name;
          if (b) brand = sanitizeExtractedText(b, 60);
        }
        if (!description && typeof prod.description === "string") {
          description = sanitizeExtractedText(prod.description, 220);
        }
        if (!category && typeof prod.category === "string") {
          category = sanitizeExtractedText(prod.category, 80);
        }
        if (!price && prod.offers) {
          const offer = Array.isArray(prod.offers) ? prod.offers[0] : prod.offers;
          const amount = offer?.price ?? offer?.lowPrice;
          const curr = offer?.priceCurrency || "";
          if (amount !== undefined && amount !== null && String(amount).trim() !== "") {
            price = sanitizeExtractedText(`${amount} ${curr}`.trim(), 40);
          }
        }
        if (title) break;
      }
    } catch {
      // Ignore malformed JSON-LD blocks
    }
  }

  // 2. OpenGraph / Twitter / standard meta tags
  const ogTitle = extractMetaContent(html, "property", "og:title") || extractMetaContent(html, "name", "twitter:title");
  if (!title && isUsefulProductTitle(ogTitle)) {
    title = ogTitle.slice(0, 160);
  }

  if (!title) {
    const titleTagMatch = html.match(/<title\b[^>]*>([\s\S]{2,300}?)<\/title>/i);
    if (titleTagMatch && titleTagMatch[1]) {
      const cleanTitleTag = sanitizeExtractedText(titleTagMatch[1], 160);
      if (isUsefulProductTitle(cleanTitleTag)) {
        title = cleanTitleTag;
      }
    }
  }

  if (!description) {
    description = (
      extractMetaContent(html, "property", "og:description") ||
      extractMetaContent(html, "name", "description") ||
      extractMetaContent(html, "name", "twitter:description")
    ).slice(0, 220);
  }

  if (!brand) {
    brand = (
      extractMetaContent(html, "property", "product:brand") ||
      extractMetaContent(html, "property", "og:brand") ||
      extractMetaContent(html, "name", "brand")
    ).slice(0, 60);
  }

  if (!price) {
    const amt =
      extractMetaContent(html, "property", "product:price:amount") ||
      extractMetaContent(html, "property", "og:price:amount") ||
      extractMetaContent(html, "name", "twitter:data1");
    const curr =
      extractMetaContent(html, "property", "product:price:currency") ||
      extractMetaContent(html, "property", "og:price:currency");
    if (amt) {
      price = sanitizeExtractedText(`${amt} ${curr}`.trim(), 40);
    }
  }

  siteName = extractMetaContent(html, "property", "og:site_name").slice(0, 60);

  const canonMatch =
    html.match(/<link\b[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']{8,600})["'][^>]*>/i) ||
    html.match(/<link\b[^>]*href\s*=\s*["']([^"']{8,600})["'][^>]*rel\s*=\s*["']canonical["'][^>]*>/i);
  if (canonMatch && canonMatch[1]) {
    canonicalUrl = canonMatch[1].trim();
  }

  return { title, brand, price, description, category, siteName, canonicalUrl };
}

async function safeFetchPublicHtml(
  initialUrl: string,
  externalSignal?: AbortSignal
): Promise<{ finalUrl: string; html: string } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  const onExternalAbort = () => controller.abort();
  if (externalSignal) {
    if (externalSignal.aborted) {
      clearTimeout(timer);
      return null;
    }
    externalSignal.addEventListener("abort", onExternalAbort, { once: true });
  }

  try {
    let currentUrl = initialUrl;

    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      const validated = await validatePublicUrlWithDns(currentUrl, true);
      if (!validated) {
        return null;
      }

      const res = await fetch(validated.toString(), {
        method: "GET",
        redirect: "manual",
        credentials: "omit",
        signal: controller.signal,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "ar,en-US;q=0.9,en;q=0.8",
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        // Drain/cancel body to avoid leaking sockets
        await res.body?.cancel().catch(() => {});
        if (!loc || hop === MAX_REDIRECT_HOPS) {
          return { finalUrl: validated.toString(), html: "" };
        }
        try {
          currentUrl = new URL(loc, validated).toString();
        } catch {
          return { finalUrl: validated.toString(), html: "" };
        }
        continue;
      }

      const contentType = (res.headers.get("content-type") || "").toLowerCase();
      const isReadableText =
        contentType.includes("text/html") ||
        contentType.includes("application/xhtml+xml") ||
        contentType.includes("text/plain") ||
        contentType.includes("application/json");

      if (!res.ok || !res.body || !isReadableText) {
        await res.body?.cancel().catch(() => {});
        return { finalUrl: validated.toString(), html: "" };
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8", { fatal: false });
      let totalBytes = 0;
      let html = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;

        const remaining = MAX_HTML_BYTES - totalBytes;
        const slice = value.byteLength > remaining ? value.subarray(0, remaining) : value;
        totalBytes += slice.byteLength;
        html += decoder.decode(slice, { stream: true });

        if (totalBytes >= MAX_HTML_BYTES) {
          await reader.cancel().catch(() => {});
          break;
        }
      }
      html += decoder.decode();
      return { finalUrl: validated.toString(), html };
    }

    return null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    if (externalSignal) externalSignal.removeEventListener("abort", onExternalAbort);
  }
}

export function extractUrlFromUserQuery(rawQuery: string): { url: string; surroundingText: string } | null {
  const text = (rawQuery || "").trim();
  if (!text) return null;

  // Match full http(s):// URLs or bare www. / popular store URLs anywhere inside the user message
  const urlPattern =
    /(https?:\/\/[^\s<>"'`]+|(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)+\/[^\s<>"'`]+)/i;
  const match = text.match(urlPattern);
  if (!match) return null;

  let candidate = match[1].replace(/[.,!?;:)\]}»"'،؟]+$/g, "").trim();
  if (!candidate) return null;

  if (!/^https?:\/\//i.test(candidate)) {
    // Only treat bare domain/path as a URL if it has a valid TLD and path
    if (!/^(?:www\.)?[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\//i.test(candidate)) {
      return null;
    }
    candidate = `https://${candidate}`;
  }

  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    const surroundingText = text
      .replace(match[0], " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 240);
    return { url: parsed.toString(), surroundingText };
  } catch {
    return null;
  }
}

export async function analyzeProductUrlInQuery(
  rawQuery: string,
  externalSignal?: AbortSignal
): Promise<AnalyzedProductLink | null> {
  const extracted = extractUrlFromUserQuery(rawQuery);
  if (!extracted) return null;

  let initialUrlObj: URL;
  try {
    initialUrlObj = new URL(extracted.url);
  } catch {
    return null;
  }

  // Strictly block unsafe / internal / private URLs immediately (zero outbound traffic)
  const validatedInitial = await validatePublicUrlWithDns(extracted.url, true);
  if (!validatedInitial) {
    return {
      originalUrl: extracted.url,
      finalUrl: "",
      storeDomain: "",
      storeName: "",
      title: "",
      brand: "",
      price: "",
      description: "",
      category: "",
      productId: "",
      urlSlugKeywords: "",
      countryHint: "",
      surroundingText: extracted.surroundingText,
      fetchedFromPage: false,
      blockedUnsafeUrl: true,
    };
  }

  const fetched = await safeFetchPublicHtml(validatedInitial.toString(), externalSignal);
  const finalUrlStr = fetched?.finalUrl || validatedInitial.toString();

  let finalUrlObj = initialUrlObj;
  try {
    finalUrlObj = new URL(finalUrlStr);
  } catch {
    finalUrlObj = validatedInitial;
  }

  const htmlMeta = fetched?.html ? extractMetadataFromHtml(fetched.html) : null;

  // If HTML exposed a valid public canonical URL, also mine its slug for richer product keywords
  let slugSourceUrlObj = finalUrlObj;
  if (htmlMeta?.canonicalUrl) {
    try {
      const canonObj = new URL(htmlMeta.canonicalUrl, finalUrlObj);
      if (
        (canonObj.protocol === "https:" || canonObj.protocol === "http:") &&
        !isPrivateOrInternalHost(canonObj.hostname)
      ) {
        slugSourceUrlObj = canonObj;
      }
    } catch {
      // ignore invalid canonical
    }
  }

  const { slugKeywords, productId } = extractSlugAndIdFromUrl(slugSourceUrlObj);
  const storeDomain = finalUrlObj.hostname.toLowerCase().replace(/^www\./, "");
  const storeName = htmlMeta?.siteName || deriveStoreNameFromHost(storeDomain);
  const title = htmlMeta?.title || slugKeywords || "";
  const countryHint = detectCountryHintFromUrl(slugSourceUrlObj) || detectCountryHintFromUrl(finalUrlObj);

  return {
    originalUrl: extracted.url,
    finalUrl: finalUrlStr,
    storeDomain,
    storeName,
    title,
    brand: htmlMeta?.brand || "",
    price: htmlMeta?.price || "",
    description: htmlMeta?.description || "",
    category: htmlMeta?.category || "",
    productId,
    urlSlugKeywords: slugKeywords,
    countryHint,
    surroundingText: extracted.surroundingText,
    fetchedFromPage: Boolean(htmlMeta?.title || htmlMeta?.description || htmlMeta?.price),
  };
}
