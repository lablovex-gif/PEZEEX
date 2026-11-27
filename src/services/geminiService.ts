export interface ProductAlternative {
  name: string;
  price: string;
  description: string;
  similarity: string;
  link: string;
  exactUrl: string;
  imageUrl?: string;
  store: string;
  storeDomain?: string;
  logoUrl?: string;
  searchKey?: string;
  isPromo?: boolean;
}

export interface ProductsResponse {
  alternatives: ProductAlternative[];
  message?: string;
}

const MAX_CLIENT_STREAM_CHARS = 256 * 1024;

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function sanitizeClientAlternatives(rawList: unknown): ProductAlternative[] {
  if (!Array.isArray(rawList)) return [];
  const mapped = rawList
    .slice(0, 18)
    .filter((item): item is Record<string, any> => Boolean(item && typeof item === "object" && !Array.isArray(item)))
    .map((item) => ({
      name: typeof item.name === "string" ? item.name.slice(0, 160) : "",
      price: typeof item.price === "string" ? item.price.slice(0, 40) : "-",
      description: typeof item.description === "string" ? item.description.slice(0, 220) : "",
      similarity: typeof item.similarity === "string" ? item.similarity.slice(0, 20) : "85%",
      link: typeof item.link === "string" ? item.link.slice(0, 1200) : "",
      exactUrl: typeof item.exactUrl === "string" ? item.exactUrl.slice(0, 1200) : "",
      imageUrl: typeof item.imageUrl === "string" ? item.imageUrl.slice(0, 300) : undefined,
      store: typeof item.store === "string" ? item.store.slice(0, 80) : "",
      storeDomain: typeof item.storeDomain === "string" ? item.storeDomain.slice(0, 120) : undefined,
      logoUrl: typeof item.logoUrl === "string" ? item.logoUrl.slice(0, 300) : undefined,
      searchKey: typeof item.searchKey === "string" ? item.searchKey.slice(0, 120) : undefined,
      isPromo: Boolean(item.isPromo),
    }))
    .filter((item) => item.name.length > 0 && item.store.length > 0);

  const seenStores = new Set<string>();
  const deduped: ProductAlternative[] = [];
  for (const item of mapped) {
    const storeKey = (item.storeDomain || item.store).toLowerCase().trim().replace(/^www\./, "");
    if (!storeKey || seenStores.has(storeKey)) continue;
    seenStores.add(storeKey);
    deduped.push(item);
  }
  return deduped;
}

function isMissingApiRouteJson(status: number, data: any): boolean {
  if (status !== 404 || !data || typeof data !== "object") return false;
  const errStr = String(data.error || "").toLowerCase().trim();
  return errStr === "api endpoint not found." || errStr === "not found";
}

function buildHttpApiError(status: number, statusText: string, data: any, isStreamServerError: boolean): Error {
  const detailedMessage =
    (data && typeof data === "object" && (data.message || data.details || data.error)) ||
    (status === 504
      ? "Search request timed out. Please try again."
      : status >= 500
        ? "Temporary server error while searching. Please try again."
        : `HTTP error ${status}: ${statusText}`);
  const err: any = new Error(String(detailedMessage));
  err.status = status;
  err.data = data;
  err.isServerError = status >= 500;
  err.isTimeout = status === 504 || /timed?\s*out/i.test(String(detailedMessage));
  if (isStreamServerError) {
    err.isStreamServerError = true;
  }
  return err;
}

export async function getProductAlternativesStream(
  productName: string,
  language: string = "العربية",
  onBatch?: (partial: ProductsResponse) => void,
  country?: string
): Promise<ProductsResponse | null> {
  const safeProductName = (productName || "").trim().slice(0, 1500);
  const safeLanguage = (language || "العربية").trim().slice(0, 40);
  const safeCountry = typeof country === "string" && /^[a-zA-Z]{2}$/.test(country.trim())
    ? country.trim().toUpperCase()
    : "";
  const streamEndpoints = ["/api/search-stream", "/api/search.php?stream=1"];
  const streamPayload = JSON.stringify({
    productName: safeProductName,
    language: safeLanguage,
    country: safeCountry,
  });

  const streamAbort = new AbortController();
  const streamTimer = setTimeout(() => streamAbort.abort(), 65000);
  try {
    for (const endpoint of streamEndpoints) {
      let res: Response;
      try {
        res = await fetch(endpoint, {
          method: "POST",
          signal: streamAbort.signal,
          headers: { "Content-Type": "application/json" },
          body: streamPayload,
        });
      } catch (fetchErr: any) {
        if (fetchErr?.name === "AbortError") {
          const timeoutErr: any = new Error("Search request timed out. Please try again.");
          timeoutErr.isTimeout = true;
          timeoutErr.isStreamServerError = true;
          throw timeoutErr;
        }
        // Network error / transient disconnect on /api/search-stream: fall back directly to /api/search
        break;
      }

      const contentType = (res.headers.get("content-type") || "").toLowerCase();

      if (res.status === 429) {
        const errData = await res.json().catch(() => ({}));
        throw buildHttpApiError(res.status, res.statusText, errData, true);
      }

      // If endpoint responded directly with JSON (error or complete result), handle immediately without a duplicate request
      if (contentType.includes("application/json")) {
        const data: any = await res.json().catch(() => ({}));
        if (isMissingApiRouteJson(res.status, data)) {
          continue;
        }
        if (res.ok && Array.isArray(data?.alternatives)) {
          const parsedRes: ProductsResponse = {
            alternatives: sanitizeClientAlternatives(data.alternatives),
            message: typeof data.message === "string" ? data.message.slice(0, 300) : undefined,
          };
          onBatch?.(parsedRes);
          return parsedRes;
        }
        throw buildHttpApiError(res.status, res.statusText, data, true);
      }

      // Check 5xx BEFORE text/html so reverse-proxy 502/503/504 HTML pages fall back to /api/search retry instead of .php
      if (res.status >= 500) {
        if (res.status === 504) {
          throw buildHttpApiError(res.status, res.statusText, {}, true);
        }
        // Transient 502/503 on streaming endpoint: fall back cleanly to standard /api/search (which includes a retry)
        break;
      }

      if (res.ok && res.body && contentType.includes("text/event-stream")) {
        const reader = res.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";
        let totalChars = 0;
        let latestResponse: ProductsResponse | null = null;
        let receivedDone = false;

        const processEventBlock = (evt: string): ProductsResponse | null => {
          const lines = evt.split(/\r?\n/);
          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed.startsWith("data:")) continue;
            const rawPayload = trimmed.slice(5).trim();
            if (!rawPayload) continue;
            let parsed: any = null;
            try {
              parsed = JSON.parse(rawPayload);
            } catch {
              continue;
            }

            if (parsed.type === "error") {
              if (latestResponse && latestResponse.alternatives.length > 0) {
                return latestResponse;
              }
              const errText =
                typeof parsed.details === "string"
                  ? parsed.details
                  : (typeof parsed.error === "string" ? parsed.error : "Search stream failed");
              const streamErr: any = new Error(errText);
              streamErr.isStreamServerError = true;
              streamErr.isServerError = true;
              streamErr.isTimeout = /timed?\s*out/i.test(errText);
              throw streamErr;
            }
            const cleanMessage = typeof parsed.message === "string" ? parsed.message.slice(0, 300) : undefined;
            if (parsed.type === "batch") {
              latestResponse = {
                alternatives: sanitizeClientAlternatives(parsed.alternatives),
                message: cleanMessage,
              };
              onBatch?.(latestResponse);
            } else if (parsed.type === "done") {
              receivedDone = true;
              latestResponse = {
                alternatives: sanitizeClientAlternatives(parsed.alternatives),
                message: cleanMessage,
              };
              onBatch?.(latestResponse);
              return latestResponse;
            }
          }
          return null;
        };

        while (true) {
          const { done, value } = await reader.read();
          if (done) {
            const flushed = decoder.decode();
            if (flushed) buffer += flushed;
            if (buffer.trim()) {
              const trailingBlocks = buffer.split(/\r?\n\r?\n/);
              for (const block of trailingBlocks) {
                const completed = processEventBlock(block);
                if (completed) return completed;
              }
            }
            break;
          }
          const chunkText = decoder.decode(value, { stream: true });
          totalChars += chunkText.length;
          if (totalChars > MAX_CLIENT_STREAM_CHARS) {
            streamAbort.abort();
            break;
          }
          buffer += chunkText;

          const events = buffer.split(/\r?\n\r?\n/);
          buffer = events.pop() || "";

          for (const evt of events) {
            const completed = processEventBlock(evt);
            if (completed) return completed;
          }
        }

        if (latestResponse && (latestResponse.alternatives.length > 0 || receivedDone)) {
          return latestResponse;
        }
        // Stream ended cleanly with no items and no done event; fall back once to standard endpoint
        break;
      }

      // Only try PHP stream fallback if Express route wasn't mounted (non-JSON 404 or SPA HTML 200)
      if (res.status === 404 || contentType.includes("text/html")) {
        continue;
      }
    }
  } catch (err: any) {
    if (err?.status === 429 || err?.isStreamServerError) throw err;
    console.warn("Streaming search unavailable, falling back to /api/search", err?.message || err);
  } finally {
    clearTimeout(streamTimer);
  }

  return getProductAlternatives(productName, language, country);
}

export async function getProductAlternatives(
  productName: string,
  language: string = "العربية",
  country?: string
): Promise<ProductsResponse | null> {
  const safeLanguage = (language || "العربية").trim().slice(0, 40);
  const safeCountry = typeof country === "string" && /^[a-zA-Z]{2}$/.test(country.trim())
    ? country.trim().toUpperCase()
    : "";
  const requestBody = JSON.stringify({
    productName: (productName || "").trim().slice(0, 1500),
    language: safeLanguage,
    country: safeCountry,
  });

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 55000);

  const requestOptions: RequestInit = {
    method: "POST",
    signal: controller.signal,
    headers: {
      "Content-Type": "application/json",
    },
    body: requestBody,
  };

  let response: Response | null = null;
  let parsedResponseData: any = null;
  let lastError: any = null;

  const candidateEndpoints = [
    "/api/search",
    "/api/search.php",
    "api/search.php",
    "/public/api/search.php",
    "public/api/search.php"
  ];

  try {
    for (let idx = 0; idx < candidateEndpoints.length; idx++) {
      const endpoint = candidateEndpoints[idx];
      const maxAttempts = idx === 0 ? 2 : 1; // Retry primary /api/search once on transient network/502/503 glitches

      for (let attempt = 0; attempt < maxAttempts; attempt++) {
        try {
          const res = await fetch(endpoint, requestOptions);
          const ct = (res.headers.get("content-type") || "").toLowerCase();

          // Any JSON response from the API (including 400/403/404/429/500/503) is authoritative unless it's a missing-route 404
          if (ct.includes("application/json")) {
            const data: any = await res.json().catch(() => ({}));
            if (isMissingApiRouteJson(res.status, data)) {
              break; // Try next fallback endpoint
            }
            if ((res.status === 502 || res.status === 503) && attempt + 1 < maxAttempts) {
              await sleepMs(1000);
              continue;
            }
            response = res;
            parsedResponseData = data;
            break;
          }

          // Reverse-proxy 5xx (even HTML 502/503/504) means the route exists but the server had a temporary error
          if (res.status >= 500) {
            if ((res.status === 502 || res.status === 503) && attempt + 1 < maxAttempts) {
              await sleepMs(1000);
              continue;
            }
            throw buildHttpApiError(res.status, res.statusText, {}, false);
          }

          // Non-JSON 404 or SPA HTML 200 -> try next endpoint (e.g., static PHP hosting)
          if (res.status === 404 || ct.includes("text/html")) {
            break;
          }

          response = res;
          break;
        } catch (err: any) {
          if (err?.name === "AbortError") {
            const timeoutErr: any = new Error("Search request timed out. Please try again.");
            timeoutErr.isTimeout = true;
            throw timeoutErr;
          }
          if (err?.isServerError || err?.status) {
            throw err;
          }
          if (attempt + 1 < maxAttempts) {
            await sleepMs(1000);
            continue;
          }
          if (!lastError) lastError = err;
        }
      }

      if (response) break;
    }

    if (response && response.ok) {
      const data: any = parsedResponseData ?? (await response.json());
      return {
        alternatives: sanitizeClientAlternatives(data?.alternatives),
        message: typeof data?.message === "string" ? data.message.slice(0, 300) : undefined,
      };
    }

    if (response && !response.ok) {
      const errData = parsedResponseData ?? (await response.json().catch(() => ({})));
      throw buildHttpApiError(response.status, response.statusText, errData, false);
    }

    const fallbackErr: any = lastError || new Error(
      safeLanguage === "العربية"
        ? "تعذر الاتصال بخدمة البحث مؤقتاً. يرجى إعادة المحاولة."
        : "Unable to reach the search service right now. Please try again."
    );
    fallbackErr.isServerError = true;
    throw fallbackErr;
  } finally {
    clearTimeout(timeoutId);
  }
}
