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
  try {
    const res = await fetch("/api/search-stream", {
      method: "POST",
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
      let latestResponse: ProductsResponse | null = null;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

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
              const streamErr: any = new Error(parsed.details || parsed.error || "Search stream failed");
              streamErr.isStreamServerError = true;
              throw streamErr;
            }
            if (parsed.type === "batch") {
              latestResponse = {
                alternatives: parsed.alternatives || [],
                message: parsed.message,
              };
              onBatch?.(latestResponse);
            } else if (parsed.type === "done") {
              latestResponse = {
                alternatives: parsed.alternatives || [],
                message: parsed.message,
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

  const requestOptions = {
    method: "POST",
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
    const data: ProductsResponse = await response.json();
    return data;
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
}
