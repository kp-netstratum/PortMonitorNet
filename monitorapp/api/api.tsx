/*
  Generic API client utilities for making HTTP requests.
  - Respects Vite env var: VITE_API_BASE_URL
  - Supports query params, JSON bodies, timeouts, and AbortSignal
  - Strongly typed response via generics
  - Axios-based implementation
*/
import axios, { type AxiosRequestConfig, type AxiosResponse } from "axios";

type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export type ParseAs = "json" | "text" | "blob" | "arrayBuffer" | "formData";

export interface ApiRequestOptions {
  method?: HttpMethod;
  baseUrl?: string;
  query?: Record<string, string | number | boolean | null | undefined>;
  headers?: Record<string, string>;
  body?: unknown; // If passing FormData, set appropriate headers externally
  signal?: AbortSignal;
  timeoutMs?: number;
  parseAs?: ParseAs; // Default auto-detects json/text
}

function buildUrl(baseUrl: string, path: string, query?: ApiRequestOptions["query"]): string {
  const trimmedBase = baseUrl?.replace(/\/$/, "") ?? "";
  const trimmedPath = path.replace(/^\//, "");
  const url = new URL(`${trimmedBase}/${trimmedPath}`, window.location.origin);
  if (query) {
    Object.entries(query).forEach(([key, value]) => {
      if (value === undefined || value === null) return;
      url.searchParams.set(key, String(value));
    });
  }
  return url.toString();
}

// Note: Axios infers response type from headers; explicit parseAs is mapped to axios responseType in apiRequest.

export class ApiError extends Error {
  status: number;
  statusText: string;
  url: string;
  bodyText?: string;
  constructor(params: { message: string; status: number; statusText: string; url: string; bodyText?: string }) {
    super(params.message);
    this.name = "ApiError";
    this.status = params.status;
    this.statusText = params.statusText;
    this.url = params.url;
    this.bodyText = params.bodyText;
  }
}

export async function apiRequest<T = unknown>(path: string, options: ApiRequestOptions = {}): Promise<T> {
  const {
    method = "GET",
    baseUrl = "http://127.0.0.1:8000",
    query,
    headers = {},
    body,
    signal,
    timeoutMs,
    parseAs,
  } = options;

  const url = buildUrl(baseUrl, path);

  const isFormData = typeof FormData !== "undefined" && body instanceof FormData;
  const finalHeaders: Record<string, string> = { ...headers };
  if (body !== undefined && !isFormData && !finalHeaders["Content-Type"]) {
    finalHeaders["Content-Type"] = "application/json";
  }

  // Map our parseAs to axios's responseType where feasible.
  let responseType: AxiosRequestConfig["responseType"] | undefined;
  switch (parseAs) {
    case "json":
      responseType = "json";
      break;
    case "text":
      responseType = "text" as any; // axios supports 'text' in browsers
      break;
    case "blob":
      responseType = "blob";
      break;
    case "arrayBuffer":
      responseType = "arraybuffer";
      break;
    case "formData":
      responseType = "blob"; // we'll convert blob -> FormData after
      break;
    default:
      responseType = undefined; // let axios infer (usually JSON or text)
  }

  const controller = !signal && timeoutMs ? new AbortController() : undefined;
  const timeoutId = controller && timeoutMs ? setTimeout(() => controller.abort(), timeoutMs) : undefined;

  try {
    const axiosConfig: AxiosRequestConfig = {
      method,
      url,
      headers: finalHeaders,
      data: body,
      params: query &&
        Object.fromEntries(
          Object.entries(query).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => [k, String(v)])
        ),
      signal: signal ?? controller?.signal,
      timeout: timeoutMs,
      withCredentials: true,
      responseType,
      transitional: {
        clarifyTimeoutError: true,
      },
    };

    const response: AxiosResponse = await axios(axiosConfig);

    // Handle special case for requested FormData response
    if (parseAs === "formData") {
      const blob = response.data as Blob;
      // Convert Blob to FormData via Response API
      // eslint-disable-next-line @typescript-eslint/no-unsafe-return
      return (await new Response(blob).formData()) as unknown as T;
    }

    // eslint-disable-next-line @typescript-eslint/no-unsafe-return
    return response.data as T;
  } catch (err) {
    if (axios.isAxiosError(err)) {
      const status = err.response?.status ?? 0;
      const statusText = err.response?.statusText ?? err.message;
      const requestUrl = err.config?.url ?? buildUrl(baseUrl, path);
      let bodyText: string | undefined;
      const data = err.response?.data;
      if (typeof data === "string") bodyText = data;
      else if (data !== undefined) {
        try {
          bodyText = JSON.stringify(data);
        } catch {
          bodyText = String(data);
        }
      }
      throw new ApiError({
        message: `Request failed with status ${status}`,
        status,
        statusText,
        url: requestUrl,
        bodyText,
      });
    }
    throw err as Error;
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export const api = {
  get: <T = unknown>(path: string, opts: Omit<ApiRequestOptions, "method" | "body"> = {}) =>
    apiRequest<T>(path, { ...opts, method: "GET" }),
  post: <T = unknown>(path: string, body?: unknown, opts: Omit<ApiRequestOptions, "method" | "body"> = {}) =>
    apiRequest<T>(path, { ...opts, method: "POST", body }),
  put: <T = unknown>(path: string, body?: unknown, opts: Omit<ApiRequestOptions, "method" | "body"> = {}) =>
    apiRequest<T>(path, { ...opts, method: "PUT", body }),
  patch: <T = unknown>(path: string, body?: unknown, opts: Omit<ApiRequestOptions, "method" | "body"> = {}) =>
    apiRequest<T>(path, { ...opts, method: "PATCH", body }),
  delete: <T = unknown>(path: string, opts: Omit<ApiRequestOptions, "method" | "body"> = {}) =>
    apiRequest<T>(path, { ...opts, method: "DELETE" }),
};

export default api;