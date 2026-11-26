import type { WebMcpToolDefinition } from "../types/webmcp";

export type PezeexPageTarget = "home" | "about" | "contact" | "privacy-policy" | "terms-of-use";

interface WebMcpUiHandlers {
  onNavigate?: (page: PezeexPageTarget) => void;
  onSearchResults?: (query: string, result: { message?: string; alternatives?: unknown[] }) => void;
}

const uiHandlers: WebMcpUiHandlers = {};
let isRegistered = false;

export function bindWebMcpUiHandlers(handlers: WebMcpUiHandlers): () => void {
  uiHandlers.onNavigate = handlers.onNavigate;
  uiHandlers.onSearchResults = handlers.onSearchResults;
  return () => {
    if (uiHandlers.onNavigate === handlers.onNavigate) uiHandlers.onNavigate = undefined;
    if (uiHandlers.onSearchResults === handlers.onSearchResults) uiHandlers.onSearchResults = undefined;
  };
}

const SUPPORTED_COUNTRIES = [
  { code: "US", name: "United States", currency: "USD" },
  { code: "SA", name: "Saudi Arabia", currency: "SAR" },
  { code: "AE", name: "United Arab Emirates", currency: "AED" },
  { code: "GB", name: "United Kingdom", currency: "GBP" },
  { code: "CA", name: "Canada", currency: "CAD" },
  { code: "DE", name: "Germany", currency: "EUR" },
  { code: "FR", name: "France", currency: "EUR" },
  { code: "ES", name: "Spain", currency: "EUR" },
  { code: "IT", name: "Italy", currency: "EUR" },
  { code: "NL", name: "Netherlands", currency: "EUR" },
  { code: "EG", name: "Egypt", currency: "EGP" },
  { code: "KW", name: "Kuwait", currency: "KWD" },
  { code: "QA", name: "Qatar", currency: "QAR" },
  { code: "BH", name: "Bahrain", currency: "BHD" },
  { code: "OM", name: "Oman", currency: "OMR" },
  { code: "JO", name: "Jordan", currency: "JOD" },
  { code: "MA", name: "Morocco", currency: "MAD" },
  { code: "TR", name: "Turkey", currency: "TRY" },
  { code: "IN", name: "India", currency: "INR" },
  { code: "JP", name: "Japan", currency: "JPY" },
  { code: "AU", name: "Australia", currency: "AUD" },
  { code: "BR", name: "Brazil", currency: "BRL" },
];

export const PEZEEX_WEBMCP_TOOLS: WebMcpToolDefinition[] = [
  {
    name: "search_product_alternatives",
    description:
      "Search Pezeex for similar, lower-priced product alternatives across trusted global and local online stores by product name or product URL.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Product name, model, or product page URL to find cheaper alternatives for.",
        },
        country: {
          type: "string",
          description: "Optional two-letter ISO country code (e.g., US, SA, AE, GB, DE).",
        },
        language: {
          type: "string",
          description: "Optional preferred language name (e.g., English, العربية).",
        },
      },
      required: ["query"],
    },
    annotations: {
      readOnlyHint: true,
    },
    execute: async (input) => {
      const query = typeof input?.query === "string" ? input.query.trim() : "";
      if (!query) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: "A product name or URL query is required." }) }],
        };
      }
      const country = typeof input?.country === "string" ? input.country.trim().toUpperCase() : undefined;
      const language = typeof input?.language === "string" && input.language.trim() ? input.language.trim() : "English";

      const response = await fetch("/api/search", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ productName: query, country, language }),
      });

      const data = await response.json().catch(() => ({ error: "Invalid JSON response from server." }));
      if (!response.ok) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: data.error || "Search failed", details: data.details }) }],
        };
      }

      uiHandlers.onSearchResults?.(query, data);

      return {
        content: [{ type: "text", text: JSON.stringify(data) }],
        ...data,
      };
    },
  },
  {
    name: "get_supported_countries",
    description: "List supported shopping countries and local currencies available on Pezeex.",
    inputSchema: {
      type: "object",
      properties: {},
    },
    annotations: {
      readOnlyHint: true,
    },
    execute: async () => {
      const payload = { countries: SUPPORTED_COUNTRIES, contactEmail: "contact@pezeex.com" };
      return {
        content: [{ type: "text", text: JSON.stringify(payload) }],
        ...payload,
      };
    },
  },
  {
    name: "open_pezeex_page",
    description: "Navigate to a Pezeex informational or legal page (home, about, contact, privacy-policy, or terms-of-use).",
    inputSchema: {
      type: "object",
      properties: {
        page: {
          type: "string",
          enum: ["home", "about", "contact", "privacy-policy", "terms-of-use"],
          description: "Target page slug to open.",
        },
      },
      required: ["page"],
    },
    annotations: {
      readOnlyHint: true,
    },
    execute: async (input) => {
      const page = String(input?.page || "home") as PezeexPageTarget;
      const validPages: PezeexPageTarget[] = ["home", "about", "contact", "privacy-policy", "terms-of-use"];
      const target: PezeexPageTarget = validPages.includes(page) ? page : "home";
      uiHandlers.onNavigate?.(target);
      const url = target === "home" ? "https://pezeex.com/" : `https://pezeex.com/${target}`;
      return {
        content: [{ type: "text", text: JSON.stringify({ navigatedTo: target, url }) }],
        navigatedTo: target,
        url,
      };
    },
  },
];

/**
 * Registers Pezeex's WebMCP tools with navigator.modelContext when supported by the browser or agent harness.
 */
export function registerWebMcpTools(): void {
  if (isRegistered || typeof navigator === "undefined") return;
  const modelContext = navigator.modelContext;
  if (!modelContext) return;

  try {
    if (typeof modelContext.registerTool === "function") {
      for (const tool of PEZEEX_WEBMCP_TOOLS) {
        modelContext.registerTool(tool);
      }
      isRegistered = true;
    } else if (typeof modelContext.provideContext === "function") {
      modelContext.provideContext({ tools: PEZEEX_WEBMCP_TOOLS });
      isRegistered = true;
    }
  } catch (err) {
    console.warn("[WebMCP] Tool registration skipped:", err);
  }
}
