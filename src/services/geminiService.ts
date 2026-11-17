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

function sanitizeClientAlternatives(rawList: unknown): ProductAlternative[] {
  if (!Array.isArray(rawList)) return [];
  return rawList
    .slice(0, 24)
    .filter((item): item is Record<string, any> => Boolean(item && typeof item === "object" && !Array.isArray(item)))
    .map((item) => ({
      name: typeof item.name === "string" ? item.name.slice(0, 160) : "",
      price: typeof item.price === "string" ? item.price.slice(0, 40) : "-",
      description: typeof item.description === "string" ? item.description.slice(0, 220) : "",
      similarity: typeof item.similarity === "string" ? item.similarity.slice(0, 20) : "85%",
      link: typeof item.link === "string" ? item.link.slice(0, 500) : "",
      exactUrl: typeof item.exactUrl === "string" ? item.exactUrl.slice(0, 500) : "",
      imageUrl: typeof item.imageUrl === "string" ? item.imageUrl.slice(0, 300) : undefined,
      store: typeof item.store === "string" ? item.store.slice(0, 80) : "",
      storeDomain: typeof item.storeDomain === "string" ? item.storeDomain.slice(0, 120) : undefined,
      logoUrl: typeof item.logoUrl === "string" ? item.logoUrl.slice(0, 300) : undefined,
      searchKey: typeof item.searchKey === "string" ? item.searchKey.slice(0, 120) : undefined,
      isPromo: false,
    }))
    .filter((item) => item.name.length > 0 && item.store.length > 0);
}

export async function getProductAlternativesStream(
  productName: string,
  language: string = "العربية",
  onBatch?: (partial: ProductsResponse) => void,
  country?: string
): Promise<ProductsResponse | null> {
  const safeProductName = (productName || "").trim().slice(0, 200);
  const safeLanguage = (language || "العربية").trim().slice(0, 40);
  const safeCountry = typeof country === "string" && /^[a-zA-Z]{2}$/.test(country.trim())
    ? country.trim().toUpperCase()
    : "";
  const streamAbort = new AbortController();
  const streamTimer = setTimeout(() => streamAbort.abort(), 65000);
  try {
    const res = await fetch("/api/search-stream", {
      method: "POST",
      signal: streamAbort.signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ productName: safeProductName, language: safeLanguage, country: safeCountry }),
    });

    if (res.status === 429) {
      const errData = await res.json().catch(() => ({}));
      const detailedMessage = errData.message || errData.details || errData.error || `HTTP error ${res.status}`;
      const err: any = new Error(detailedMessage);
      err.status = res.status;
      err.data = errData;
      throw err;
    }

    const contentType = res.headers.get("content-type") || "";
    if (res.ok && res.body && contentType.includes("text/event-stream")) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder("utf-8");
      let buffer = "";
      let totalChars = 0;
      let latestResponse: ProductsResponse | null = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunkText = decoder.decode(value, { stream: true });
        totalChars += chunkText.length;
        if (totalChars > MAX_CLIENT_STREAM_CHARS) {
          streamAbort.abort();
          break;
        }
        buffer += chunkText;

        const events = buffer.split("\n\n");
        buffer = events.pop() || "";

        for (const evt of events) {
          const lines = evt.split("\n");
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
              const streamErr: any = new Error(
                typeof parsed.details === "string"
                  ? parsed.details
                  : (typeof parsed.error === "string" ? parsed.error : "Search stream failed")
              );
              streamErr.isStreamServerError = true;
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
              latestResponse = {
                alternatives: sanitizeClientAlternatives(parsed.alternatives),
                message: cleanMessage,
              };
              onBatch?.(latestResponse);
              return latestResponse;
            }
          }
        }
      }

      if (latestResponse && latestResponse.alternatives.length > 0) {
        return latestResponse;
      }
    }
  } catch (err: any) {
    if (err?.status === 429 || err?.isStreamServerError) throw err;
    // Fallback to standard /api/search or PHP bridge only when SSE streaming itself is unavailable
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
  const safeCountry = typeof country === "string" && /^[a-zA-Z]{2}$/.test(country.trim())
    ? country.trim().toUpperCase()
    : "";
  const requestBody = JSON.stringify({
    productName: (productName || "").trim().slice(0, 200),
    language: (language || "العربية").trim().slice(0, 40),
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
  let lastError: any = null;

  const candidateEndpoints = [
    "/api/search",
    "/api/search.php",
    "api/search.php",
    "/public/api/search.php",
    "public/api/search.php"
  ];

  try {
    for (const endpoint of candidateEndpoints) {
      try {
        const res = await fetch(endpoint, requestOptions);
        if (res.status !== 404) {
          response = res;
          break;
        }
      } catch (err: any) {
        if (!lastError) lastError = err;
      }
    }

    if (response && response.ok) {
      const data: any = await response.json();
      return {
        alternatives: sanitizeClientAlternatives(data?.alternatives),
        message: typeof data?.message === "string" ? data.message.slice(0, 300) : undefined,
      };
    }

    if (response && !response.ok) {
      const errData = await response.json().catch(() => ({}));
      const detailedMessage = errData.message || errData.details || errData.error || `HTTP error ${response.status}: ${response.statusText}`;
      const err: any = new Error(detailedMessage);
      err.status = response.status;
      err.data = errData;
      throw err;
    }

    throw lastError || new Error("تعذر الاتصال بخدمة البحث.");
  } finally {
    clearTimeout(timeoutId);
  }
}
