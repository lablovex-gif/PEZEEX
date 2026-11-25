import { isPrivateOrInternalHost } from "./serverUrlAnalyzer";

const TAKEADS_RESOLVE_ENDPOINT = "https://api.takeads.com/v1/product/monetize-api/v2/resolve";
const TAKEADS_CATALOG_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const TAKEADS_REQUEST_TIMEOUT_MS = 6500;
const TAKEADS_MAX_URLS_PER_BATCH = 60;

type RegionTag = "GLOBAL" | "US" | "CA" | "UK" | "EU" | "ME" | "APAC" | "LATAM";

interface CandidateStore {
  name: string;
  domain: string;
  probeUrl: string;
  regions: RegionTag[];
}

const CANDIDATE_STORES: CandidateStore[] = [
  // Global / Cross-border
  { name: "Amazon", domain: "amazon.com", probeUrl: "https://www.amazon.com/s?k=electronics", regions: ["GLOBAL", "US", "CA", "ME", "LATAM", "APAC"] },
  { name: "AliExpress", domain: "aliexpress.com", probeUrl: "https://www.aliexpress.com/wholesale?SearchText=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "Temu", domain: "temu.com", probeUrl: "https://www.temu.com/search_result.html?search_key=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "SHEIN", domain: "shein.com", probeUrl: "https://www.shein.com/pdsearch/fashion/", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "iHerb", domain: "iherb.com", probeUrl: "https://www.iherb.com/search?kw=vitamins", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "DHgate", domain: "dhgate.com", probeUrl: "https://www.dhgate.com/wholesale/search.do?searchkey=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "Banggood", domain: "banggood.com", probeUrl: "https://www.banggood.com/search/electronics.html", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "Geekbuying", domain: "geekbuying.com", probeUrl: "https://www.geekbuying.com/search/electronics/", regions: ["GLOBAL", "US", "UK", "EU"] },
  { name: "LightInTheBox", domain: "lightinthebox.com", probeUrl: "https://www.lightinthebox.com/index.php?main_page=advanced_search_result&keyword=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"] },
  { name: "Farfetch", domain: "farfetch.com", probeUrl: "https://www.farfetch.com/shopping/women/search/items.aspx?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"] },
  { name: "Nike", domain: "nike.com", probeUrl: "https://www.nike.com/w?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"] },
  { name: "Adidas", domain: "adidas.com", probeUrl: "https://www.adidas.com/us/search?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU"] },
  { name: "Decathlon", domain: "decathlon.com", probeUrl: "https://www.decathlon.com/search?q=bike", regions: ["GLOBAL", "US", "UK", "EU", "ME"] },
  { name: "Etsy", domain: "etsy.com", probeUrl: "https://www.etsy.com/search?q=gift", regions: ["GLOBAL", "US", "CA", "UK", "EU"] },
  { name: "ASOS", domain: "asos.com", probeUrl: "https://www.asos.com/search/?q=jacket", regions: ["GLOBAL", "UK", "EU", "US", "ME"] },
  { name: "Sephora", domain: "sephora.com", probeUrl: "https://www.sephora.com/search?keyword=perfume", regions: ["US", "CA", "EU", "ME"] },
  { name: "Lenovo", domain: "lenovo.com", probeUrl: "https://www.lenovo.com/us/en/search?text=laptop", regions: ["GLOBAL", "US", "UK", "EU"] },
  { name: "Samsung", domain: "samsung.com", probeUrl: "https://www.samsung.com/us/search/searchMain/?listType=g&searchTerm=phone", regions: ["GLOBAL", "US", "UK", "EU"] },

  // North America (US & CA)
  { name: "Walmart", domain: "walmart.com", probeUrl: "https://www.walmart.com/search?q=electronics", regions: ["US", "CA"] },
  { name: "Target", domain: "target.com", probeUrl: "https://www.target.com/s?searchTerm=electronics", regions: ["US"] },
  { name: "Best Buy", domain: "bestbuy.com", probeUrl: "https://www.bestbuy.com/site/searchpage.jsp?st=electronics", regions: ["US"] },
  { name: "Newegg", domain: "newegg.com", probeUrl: "https://www.newegg.com/p/pl?d=laptop", regions: ["US", "CA"] },
  { name: "Home Depot", domain: "homedepot.com", probeUrl: "https://www.homedepot.com/s/tools", regions: ["US"] },
  { name: "Lowe's", domain: "lowes.com", probeUrl: "https://www.lowes.com/search?searchTerm=tools", regions: ["US"] },
  { name: "Macy's", domain: "macys.com", probeUrl: "https://www.macys.com/shop/featured/shoes", regions: ["US"] },
  { name: "Nordstrom", domain: "nordstrom.com", probeUrl: "https://www.nordstrom.com/sr?keyword=shoes", regions: ["US"] },
  { name: "Wayfair", domain: "wayfair.com", probeUrl: "https://www.wayfair.com/keyword.php?keyword=chair", regions: ["US", "CA", "UK"] },
  { name: "Amazon Canada", domain: "amazon.ca", probeUrl: "https://www.amazon.ca/s?k=electronics", regions: ["CA"] },
  { name: "Best Buy Canada", domain: "bestbuy.ca", probeUrl: "https://www.bestbuy.ca/en-ca/search?search=electronics", regions: ["CA"] },

  // Middle East & North Africa
  { name: "Noon", domain: "noon.com", probeUrl: "https://www.noon.com/saudi-en/search/?q=electronics", regions: ["ME"] },
  { name: "Namshi", domain: "namshi.com", probeUrl: "https://en-sa.namshi.com/search?q=shoes", regions: ["ME"] },
  { name: "Amazon Saudi", domain: "amazon.sa", probeUrl: "https://www.amazon.sa/s?k=electronics", regions: ["ME"] },
  { name: "Amazon UAE", domain: "amazon.ae", probeUrl: "https://www.amazon.ae/s?k=electronics", regions: ["ME"] },
  { name: "Ounass", domain: "ounass.sa", probeUrl: "https://www.ounass.sa/search?q=bag", regions: ["ME"] },
  { name: "Trendyol", domain: "trendyol.com", probeUrl: "https://www.trendyol.com/sr?q=shoes", regions: ["ME", "EU"] },
  { name: "Jumia", domain: "jumia.com.eg", probeUrl: "https://www.jumia.com.eg/catalog/?q=electronics", regions: ["ME"] },

  // UK & Europe
  { name: "Amazon UK", domain: "amazon.co.uk", probeUrl: "https://www.amazon.co.uk/s?k=electronics", regions: ["UK"] },
  { name: "Currys", domain: "currys.co.uk", probeUrl: "https://www.currys.co.uk/search?q=laptop", regions: ["UK"] },
  { name: "Argos", domain: "argos.co.uk", probeUrl: "https://www.argos.co.uk/search/electronics/", regions: ["UK"] },
  { name: "Amazon Germany", domain: "amazon.de", probeUrl: "https://www.amazon.de/s?k=electronics", regions: ["EU"] },
  { name: "Amazon France", domain: "amazon.fr", probeUrl: "https://www.amazon.fr/s?k=electronics", regions: ["EU"] },
  { name: "Amazon Spain", domain: "amazon.es", probeUrl: "https://www.amazon.es/s?k=electronics", regions: ["EU"] },
  { name: "Amazon Italy", domain: "amazon.it", probeUrl: "https://www.amazon.it/s?k=electronics", regions: ["EU"] },
  { name: "Otto", domain: "otto.de", probeUrl: "https://www.otto.de/suche/electronics/", regions: ["EU"] },
  { name: "MediaMarkt", domain: "mediamarkt.de", probeUrl: "https://www.mediamarkt.de/de/search.html?query=electronics", regions: ["EU"] },
  { name: "Cdiscount", domain: "cdiscount.com", probeUrl: "https://www.cdiscount.com/search/10/electronics.html", regions: ["EU"] },
  { name: "Fnac", domain: "fnac.com", probeUrl: "https://www.fnac.com/SearchResult/ResultList.aspx?Search=electronics", regions: ["EU"] },
  { name: "Bol.com", domain: "bol.com", probeUrl: "https://www.bol.com/nl/nl/s/?searchtext=electronics", regions: ["EU"] },
  { name: "Zalando", domain: "zalando.de", probeUrl: "https://www.zalando.de/katalog/?q=shoes", regions: ["EU"] },

  // APAC & LATAM
  { name: "Amazon Australia", domain: "amazon.com.au", probeUrl: "https://www.amazon.com.au/s?k=electronics", regions: ["APAC"] },
  { name: "Amazon Japan", domain: "amazon.co.jp", probeUrl: "https://www.amazon.co.jp/s?k=electronics", regions: ["APAC"] },
  { name: "Amazon India", domain: "amazon.in", probeUrl: "https://www.amazon.in/s?k=electronics", regions: ["APAC"] },
  { name: "Flipkart", domain: "flipkart.com", probeUrl: "https://www.flipkart.com/search?q=electronics", regions: ["APAC"] },
  { name: "Mercado Libre", domain: "mercadolibre.com.mx", probeUrl: "https://listado.mercadolibre.com.mx/electronics", regions: ["LATAM"] },
  { name: "Amazon Brazil", domain: "amazon.com.br", probeUrl: "https://www.amazon.com.br/s?k=electronics", regions: ["LATAM"] },
];

const ME_COUNTRIES = new Set(["SA", "AE", "EG", "KW", "QA", "BH", "OM", "JO", "LB", "IQ", "MA", "DZ", "TN", "TR"]);
const EU_COUNTRIES = new Set([
  "DE", "FR", "ES", "IT", "NL", "PL", "SE", "BE", "AT", "CH", "CZ", "DK", "NO", "FI",
  "GR", "HU", "RO", "UA", "BG", "HR", "SK", "LT", "SI", "LV", "EE", "AL", "BA", "IS", "PT", "IE",
]);
const APAC_COUNTRIES = new Set(["IN", "JP", "KR", "AU", "NZ", "SG", "MY", "PH", "ID", "TH", "VN", "CN", "HK", "TW"]);
const LATAM_COUNTRIES = new Set(["BR", "MX", "AR", "CL", "CO", "PE", "UY", "EC"]);

function getRegionForCountry(countryCode: string): RegionTag {
  const cc = (countryCode || "US").toUpperCase();
  if (cc === "US") return "US";
  if (cc === "CA") return "CA";
  if (cc === "GB" || cc === "UK") return "UK";
  if (ME_COUNTRIES.has(cc)) return "ME";
  if (EU_COUNTRIES.has(cc)) return "EU";
  if (APAC_COUNTRIES.has(cc)) return "APAC";
  if (LATAM_COUNTRIES.has(cc)) return "LATAM";
  return "GLOBAL";
}

export function getTakeadsPublicKey(): string {
  return (process.env.TAKEADS_PUBLIC_KEY || "").trim();
}

export function getTakeadsSubId(): string {
  const raw = (process.env.TAKEADS_SUB_ID || "pezeex").trim();
  const clean = raw.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  return clean || "pezeex";
}

export function isTakeadsConfigured(): boolean {
  return getTakeadsPublicKey().length > 0;
}

function normalizeDomain(domain: string): string {
  return (domain || "").toLowerCase().trim().replace(/^www\./, "");
}

function isValidTrackingLink(rawUrl: unknown): rawUrl is string {
  if (typeof rawUrl !== "string") return false;
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.length > 1200 || /[\u0000-\u001F\u007F]/.test(trimmed)) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.port && parsed.port !== "443") return false;
    if (!parsed.hostname || isPrivateOrInternalHost(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

export interface TakeadsResolveResult {
  ok: boolean;
  authError?: boolean;
  linksByIri: Map<string, string>;
}

let hasLoggedAuthWarning = false;

export async function resolveTakeadsUrls(
  urls: string[],
  signal?: AbortSignal
): Promise<TakeadsResolveResult> {
  const linksByIri = new Map<string, string>();
  const publicKey = getTakeadsPublicKey();
  if (!publicKey) {
    return { ok: false, linksByIri };
  }

  const uniqueUrls: string[] = [];
  const seen = new Set<string>();
  for (const u of urls) {
    if (typeof u !== "string") continue;
    const trimmed = u.trim();
    if (!trimmed || !trimmed.startsWith("https://") || seen.has(trimmed)) continue;
    seen.add(trimmed);
    uniqueUrls.push(trimmed);
  }

  if (uniqueUrls.length === 0) {
    return { ok: true, linksByIri };
  }

  const subId = getTakeadsSubId();

  // Chunk into batches of TAKEADS_MAX_URLS_PER_BATCH
  for (let offset = 0; offset < uniqueUrls.length; offset += TAKEADS_MAX_URLS_PER_BATCH) {
    if (signal?.aborted) {
      return { ok: false, linksByIri };
    }

    const batch = uniqueUrls.slice(offset, offset + TAKEADS_MAX_URLS_PER_BATCH);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TAKEADS_REQUEST_TIMEOUT_MS);
    const onParentAbort = () => controller.abort();
    signal?.addEventListener("abort", onParentAbort, { once: true });

    try {
      const response = await fetch(TAKEADS_RESOLVE_ENDPOINT, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${publicKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          iris: batch,
          subId,
        }),
        signal: controller.signal,
      });

      if (response.status === 401 || response.status === 403) {
        if (!hasLoggedAuthWarning) {
          hasLoggedAuthWarning = true;
          console.warn(
            "[Takeads] Authentication failed (HTTP " +
              response.status +
              "). Ensure TAKEADS_PUBLIC_KEY is set to your Platform API Public Key (from Platform settings -> Platform API)."
          );
        }
        return { ok: false, authError: true, linksByIri };
      }

      if (!response.ok) {
        console.warn(`[Takeads] Resolve API returned HTTP ${response.status}`);
        return { ok: false, linksByIri };
      }

      const payload: any = await response.json();
      const entries = Array.isArray(payload?.data) ? payload.data : [];
      for (const entry of entries) {
        const iri = typeof entry?.iri === "string" ? entry.iri.trim() : "";
        const trackingLink = entry?.trackingLink;
        if (iri && isValidTrackingLink(trackingLink)) {
          linksByIri.set(iri, trackingLink.trim());
        }
      }
    } catch (err: any) {
      if (signal?.aborted) {
        return { ok: false, linksByIri };
      }
      console.warn("[Takeads] Resolve request failed:", err?.message || err);
      return { ok: false, linksByIri };
    } finally {
      clearTimeout(timeoutId);
      signal?.removeEventListener("abort", onParentAbort);
    }
  }

  return { ok: true, linksByIri };
}

interface SupportedCatalogCache {
  expiresAt: number;
  stores: CandidateStore[];
  domains: Set<string>;
}

let catalogCache: SupportedCatalogCache | null = null;
let catalogInFlight: Promise<SupportedCatalogCache | null> | null = null;

async function getVerifiedTakeadsCatalog(signal?: AbortSignal): Promise<SupportedCatalogCache | null> {
  if (!isTakeadsConfigured()) return null;

  const now = Date.now();
  if (catalogCache && now < catalogCache.expiresAt) {
    return catalogCache;
  }

  if (catalogInFlight) {
    return catalogInFlight;
  }

  catalogInFlight = (async () => {
    const probeUrls = CANDIDATE_STORES.map((s) => s.probeUrl);
    const res = await resolveTakeadsUrls(probeUrls, signal);
    if (!res.ok) {
      return catalogCache; // return stale cache if available
    }

    const supportedStores: CandidateStore[] = [];
    const supportedDomains = new Set<string>();

    for (const candidate of CANDIDATE_STORES) {
      if (res.linksByIri.has(candidate.probeUrl)) {
        supportedStores.push(candidate);
        supportedDomains.add(normalizeDomain(candidate.domain));
      }
    }

    if (supportedStores.length > 0) {
      catalogCache = {
        expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS,
        stores: supportedStores,
        domains: supportedDomains,
      };
      console.log(
        `[Takeads] Verified ${supportedStores.length} active Takeads-supported stores in catalog.`
      );
      return catalogCache;
    }

    return catalogCache;
  })().finally(() => {
    catalogInFlight = null;
  });

  return catalogInFlight;
}

export interface TakeadsPromptGuidance {
  enabled: boolean;
  storesListText: string;
  sampleStore: string;
  sampleDomain: string;
}

export async function getTakeadsPromptGuidance(
  countryCode: string,
  signal?: AbortSignal
): Promise<TakeadsPromptGuidance | null> {
  if (!isTakeadsConfigured()) return null;

  const catalog = await getVerifiedTakeadsCatalog(signal);
  if (!catalog || catalog.stores.length === 0) {
    return null;
  }

  const region = getRegionForCountry(countryCode);
  const regionalStores = catalog.stores.filter((s) => s.regions.includes(region));
  const globalFallbackStores = catalog.stores.filter(
    (s) => !s.regions.includes(region) && s.regions.includes("GLOBAL")
  );
  const prioritized = [...regionalStores, ...globalFallbackStores];
  const list = prioritized.length > 0 ? prioritized : catalog.stores;

  const storesListText = list
    .slice(0, 22)
    .map((s) => `${s.name} (${s.domain})`)
    .join(", ");

  const sample = list[0] || { name: "AliExpress", domain: "aliexpress.com" };

  return {
    enabled: true,
    storesListText,
    sampleStore: sample.name,
    sampleDomain: sample.domain,
  };
}

/**
 * Strictly filters product alternatives to Takeads-supported merchants and rewrites
 * every exactUrl/link to its real Takeads Server-to-Server affiliate trackingLink.
 *
 * Uses a per-search cache map so streaming batches never re-resolve the same URL twice.
 */
export async function filterAndMonetizeAlternativesWithTakeads<
  T extends { exactUrl: string; storeDomain?: string; link?: string }
>(
  items: T[],
  signal?: AbortSignal,
  perSearchCache?: Map<string, string | null>
): Promise<T[]> {
  if (!items || items.length === 0) return [];
  if (!isTakeadsConfigured()) return items;

  const cache = perSearchCache || new Map<string, string | null>();
  const urlsToResolve: string[] = [];

  for (const item of items) {
    const url = (item.exactUrl || "").trim();
    if (!url) continue;
    if (!cache.has(url)) {
      urlsToResolve.push(url);
    }
  }

  let resolveSucceeded = true;
  if (urlsToResolve.length > 0) {
    const res = await resolveTakeadsUrls(urlsToResolve, signal);
    resolveSucceeded = res.ok;
    if (res.ok) {
      for (const u of urlsToResolve) {
        const trackingLink = res.linksByIri.get(u);
        cache.set(u, trackingLink || null);
      }
    }
  }

  if (!resolveSucceeded) {
    // Graceful fallback: if Takeads API is temporarily unreachable, filter by cached supported domains
    // when available so the backup convertlink.com client script can still monetize them.
    if (catalogCache && catalogCache.domains.size > 0) {
      const domainFiltered = items.filter((item) => {
        const d = normalizeDomain(item.storeDomain || "");
        return d && catalogCache!.domains.has(d);
      });
      return domainFiltered.length > 0 ? domainFiltered : items;
    }
    return items;
  }

  const monetized: T[] = [];
  for (const item of items) {
    const originalUrl = (item.exactUrl || "").trim();
    const trackingLink = cache.get(originalUrl);
    if (trackingLink) {
      monetized.push({
        ...item,
        exactUrl: trackingLink,
        link: trackingLink,
      });
    }
  }

  return monetized;
}
