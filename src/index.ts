import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import express, { Request, Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { CapturedExecutionContext, DEFAULT_CDP_WS_URL, WmpfCdpClient } from "./cdp.js";

const DEFAULT_MCP_PORT = 43_827;
const DEFAULT_MAX_LENGTH = 20_000;
const DEFAULT_MCP_TOKEN = "wmpf-local-token";
const MCP_PORT = parseInt(process.env.MCP_PORT ?? `${DEFAULT_MCP_PORT}`, 10);
const MCP_TOKEN = process.env.MCP_TOKEN ?? DEFAULT_MCP_TOKEN;
const cdp = new WmpfCdpClient();
const attachedTargets = new Map<string, string>();
let selectedAppservice: AppserviceSelection | undefined;

type JsonObject = Record<string, unknown>;
type RequestSource = "cdp" | "wx" | "fetch" | "xhr";

interface NormalizedRequest {
  id: string;
  source: RequestSource;
  method: string;
  url: string;
  path: string;
  query: JsonObject;
  requestHeaders: JsonObject;
  requestBodyPreview: unknown;
  requestBodyRaw?: unknown;
  statusCode?: number;
  responseHeaders: JsonObject;
  responseBodyPreview?: unknown;
  responseBodyRaw?: unknown;
  durationMs?: number;
  timestamp?: string;
  callStack?: string;
  cdpRequestId?: string;
  raw?: unknown;
}

interface RequestFilters {
  limit?: number;
  keyword?: string;
  domain?: string;
  pathPrefix?: string;
}

interface TargetInfo {
  targetId: string;
  type?: string;
  title?: string;
  url?: string;
  attached?: boolean;
}

interface AppserviceSelection {
  targetId: string;
  sessionId: string;
  contextId: number;
  targetInfo: TargetInfo;
  context: CapturedExecutionContext;
  probe: JsonObject;
  score: number;
}

const DEFAULT_KEYWORDS = [
  "sign",
  "signature",
  "token",
  "timestamp",
  "nonce",
  "encrypt",
  "decrypt",
  "AES",
  "RSA",
  "MD5",
  "SHA",
  "Hmac",
  "Authorization",
  "openid",
  "unionid",
  "session_key",
  "wx.request",
  "baseUrl",
  "api"
];

const ID_FIELD_REGEX = /(^|\.|_|-)(userId|uid|memberId|accountId|orderId|couponId|addressId|invoiceId|recordId|id)$/i;
const SENSITIVE_FIELD_REGEX = /(phone|mobile|email|idCard|identity|realName|address|bankCard|openid|unionid|session_key|token|cookie|authorization|password|secret)/i;
const AUTH_FIELD_REGEX = /(authorization|token|session|cookie|openid|unionid|userId|memberId|uid|sign|signature|timestamp|nonce)/i;
const DANGEROUS_CLICK_REGEX = /(支付|提交订单|删除|注销|退款|提现|确认支付)/;

function textResult(value: unknown) {
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(value, null, 2)
      }
    ]
  };
}

function errorTextResult(message: string, extra: JsonObject = {}) {
  return textResult({
    ok: false,
    error: message,
    ...extra
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function clampLimit(value: number | undefined, defaultValue: number, maxValue: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return defaultValue;
  }

  return Math.max(1, Math.min(maxValue, Math.floor(value)));
}

async function safeTool<T>(handler: () => Promise<T> | T) {
  try {
    return textResult(await handler());
  } catch (error) {
    return errorTextResult(errorMessage(error));
  }
}

function requireCdpConnected(): void {
  if (!cdp.isConnected()) {
    throw new Error("CDP WebSocket is not connected. Call connect_wmpf first.");
  }
}

async function evalJson<T = unknown>(
  expression: string,
  options: { returnByValue?: boolean; awaitPromise?: boolean } = {}
): Promise<T> {
  requireCdpConnected();

  const result = await cdp.eval(expression, {
    returnByValue: options.returnByValue ?? true,
    awaitPromise: options.awaitPromise ?? true
  });

  const remoteObject = result.result as
    | {
        type?: string;
        value?: T;
        unserializableValue?: string;
        objectId?: string;
        description?: string;
      }
    | undefined;

  if (result.exceptionDetails) {
    throw new Error(`Runtime.evaluate exception: ${JSON.stringify(result.exceptionDetails)}`);
  }

  if (!remoteObject) {
    return result as T;
  }

  if ("value" in remoteObject) {
    return remoteObject.value as T;
  }

  return remoteObject as T;
}

async function sleep(ms: number): Promise<void> {
  await new Promise(resolve => setTimeout(resolve, ms));
}

function remoteObjectValue<T = unknown>(result: JsonObject): T {
  const remoteObject = result.result as
    | {
        value?: T;
        unserializableValue?: string;
        objectId?: string;
        description?: string;
      }
    | undefined;

  if (!remoteObject) {
    return result as T;
  }

  if ("value" in remoteObject) {
    return remoteObject.value as T;
  }

  return remoteObject as T;
}

async function attachToTarget(targetId: string): Promise<string> {
  const existing = attachedTargets.get(targetId);
  if (existing) {
    return existing;
  }

  const attached = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const sessionId = String(attached.sessionId ?? "");
  if (!sessionId) {
    throw new Error(`Target.attachToTarget returned no sessionId for ${targetId}`);
  }

  attachedTargets.set(targetId, sessionId);
  return sessionId;
}

async function getTargets(): Promise<TargetInfo[]> {
  requireCdpConnected();
  const result = await cdp.send("Target.getTargets");
  const targetInfos = Array.isArray(result.targetInfos) ? result.targetInfos : [];
  return targetInfos
    .filter(isRecord)
    .map(item => ({
      targetId: String(item.targetId ?? ""),
      type: typeof item.type === "string" ? item.type : undefined,
      title: typeof item.title === "string" ? item.title : undefined,
      url: typeof item.url === "string" ? item.url : undefined,
      attached: typeof item.attached === "boolean" ? item.attached : undefined
    }))
    .filter(item => item.targetId);
}

function scoreTarget(target: TargetInfo): number {
  const text = `${target.type ?? ""} ${target.title ?? ""} ${target.url ?? ""}`.toLowerCase();
  let score = 0;
  if (/appservice|service|worker|jscontext/.test(text)) score += 8;
  if (/app|wx|miniprogram|miniapp/.test(text)) score += 3;
  if (target.type && !["page", "iframe"].includes(target.type)) score += 2;
  return score;
}

function scoreProbe(probe: JsonObject): number {
  let score = 0;
  if (probe.hasWxRequest === true) score += 10;
  if (probe.hasWx === true) score += 4;
  if (probe.hasRequire === true) score += 6;
  if (probe.hasGetCurrentPages === true) score += 4;
  if (probe.hasApp === true) score += 2;
  if (probe.hasVuexStore === true) score += 5;
  return score;
}

async function probeRuntimeContext(target: TargetInfo, sessionId: string, context: CapturedExecutionContext): Promise<AppserviceSelection | undefined> {
  try {
    const result = await cdp.send(
      "Runtime.evaluate",
      {
        contextId: context.id,
        returnByValue: true,
        awaitPromise: true,
        expression: `(() => {
          const out = {
            hasWx: typeof wx !== "undefined",
            hasWxRequest: typeof wx !== "undefined" && typeof wx.request === "function",
            hasRequire: typeof require === "function",
            hasGetCurrentPages: typeof getCurrentPages === "function",
            hasApp: typeof getApp === "function",
            hasVuexStore: false,
            windowKeys: typeof globalThis === "object" ? Object.keys(globalThis).filter(k => /wx|store|vue|app|route|config|request/i.test(k)).slice(0, 50) : []
          };
          try {
            const store = typeof require === "function" ? require("store/index.js")?.store : null;
            out.hasVuexStore = !!(store && store.state && store.commit);
          } catch {}
          return out;
        })()`
      },
      DEFAULT_MAX_LENGTH,
      sessionId
    );
    const probe = remoteObjectValue<JsonObject>(result);
    const score = scoreTarget(target) + scoreProbe(probe);
    if (score <= 0) {
      return undefined;
    }

    return { targetId: target.targetId, sessionId, contextId: context.id, targetInfo: target, context, probe, score };
  } catch {
    return undefined;
  }
}

async function selectAppserviceContext(force = false): Promise<AppserviceSelection> {
  requireCdpConnected();
  if (!force && selectedAppservice) {
    return selectedAppservice;
  }

  const targets = (await getTargets()).sort((a, b) => scoreTarget(b) - scoreTarget(a));
  const candidates: AppserviceSelection[] = [];

  for (const target of targets) {
    try {
      const sessionId = await attachToTarget(target.targetId);
      await cdp.send("Runtime.enable", {}, DEFAULT_MAX_LENGTH, sessionId).catch(() => ({}));
      await sleep(250);
      const contexts = cdp.getRuntimeContexts().filter(context => context.sessionId === sessionId);
      for (const context of contexts) {
        const candidate = await probeRuntimeContext(target, sessionId, context);
        if (candidate) {
          candidates.push(candidate);
        }
      }
    } catch {
      continue;
    }
  }

  candidates.sort((a, b) => b.score - a.score);
  const selected = candidates[0];
  if (!selected) {
    throw new Error("No appservice-like Runtime execution context found. Try opening the mini program page first.");
  }

  selectedAppservice = selected;
  return selected;
}

async function evalInAppservice<T = unknown>(expression: string, forceSelect = false): Promise<T> {
  const selected = await selectAppserviceContext(forceSelect);
  const result = await cdp.send(
    "Runtime.evaluate",
    {
      expression,
      returnByValue: true,
      awaitPromise: true,
      contextId: selected.contextId
    },
    DEFAULT_MAX_LENGTH,
    selected.sessionId
  );

  if (result.exceptionDetails) {
    throw new Error(`Runtime.evaluate appservice exception: ${JSON.stringify(result.exceptionDetails)}`);
  }

  return remoteObjectValue<T>(result);
}

function js(value: unknown): string {
  return JSON.stringify(value);
}

function isRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function truncateString(value: string, maxLength = DEFAULT_MAX_LENGTH): string {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength)}...[truncated ${value.length - maxLength} chars]`;
}

function maskValue(value: string): string {
  if (value.length <= 6) {
    return "***";
  }

  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

function maskScalar(value: unknown): unknown {
  if (typeof value !== "string") {
    return value;
  }

  return value
    .replace(/\b1[3-9]\d{9}\b/g, phone => `${phone.slice(0, 3)}****${phone.slice(-4)}`)
    .replace(/\b\d{15}(\d{2}[\dXx])?\b/g, id => `${id.slice(0, 4)}********${id.slice(-4)}`)
    .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, email => {
      const [name, domain] = email.split("@");
      return `${name.slice(0, 2)}***@${domain}`;
    });
}

function sanitizeSensitive(value: unknown, keyPath = "", depth = 0): unknown {
  if (depth > 6) {
    return "[max-depth]";
  }

  if (SENSITIVE_FIELD_REGEX.test(keyPath)) {
    return typeof value === "string" ? maskValue(value) : "[masked]";
  }

  if (Array.isArray(value)) {
    return value.slice(0, 50).map(item => sanitizeSensitive(item, keyPath, depth + 1));
  }

  if (isRecord(value)) {
    const out: JsonObject = {};
    for (const [key, item] of Object.entries(value).slice(0, 120)) {
      const nextPath = keyPath ? `${keyPath}.${key}` : key;
      out[key] = sanitizeSensitive(item, nextPath, depth + 1);
    }
    return out;
  }

  return maskScalar(value);
}

function toPreview(value: unknown, maxLength = 2_000): unknown {
  const sanitized = sanitizeSensitive(value);
  if (typeof sanitized === "string") {
    return truncateString(sanitized, maxLength);
  }

  const text = JSON.stringify(sanitized);
  if (text.length <= maxLength) {
    return sanitized;
  }

  return `${text.slice(0, maxLength)}...[truncated ${text.length - maxLength} chars]`;
}

function tryParseJson(value: unknown): unknown {
  if (typeof value !== "string") {
    return value;
  }

  const trimmed = value.trim();
  if (!trimmed || !/^[\[{]/.test(trimmed)) {
    return value;
  }

  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function collectFieldKeys(value: unknown, prefix = "", out = new Set<string>(), depth = 0): Set<string> {
  const parsed = tryParseJson(value);
  if (depth > 5 || !parsed) {
    return out;
  }

  if (Array.isArray(parsed)) {
    for (const item of parsed.slice(0, 5)) {
      collectFieldKeys(item, prefix, out, depth + 1);
    }
    return out;
  }

  if (isRecord(parsed)) {
    for (const [key, item] of Object.entries(parsed).slice(0, 80)) {
      const next = prefix ? `${prefix}.${key}` : key;
      out.add(next);
      collectFieldKeys(item, next, out, depth + 1);
    }
  }

  return out;
}

function collectMatchingFields(value: unknown, regex: RegExp, location: string, out: JsonObject[] = [], depth = 0): JsonObject[] {
  const parsed = tryParseJson(value);
  if (depth > 6 || !parsed) {
    return out;
  }

  if (Array.isArray(parsed)) {
    parsed.slice(0, 20).forEach((item, index) => collectMatchingFields(item, regex, `${location}[${index}]`, out, depth + 1));
    return out;
  }

  if (isRecord(parsed)) {
    for (const [key, item] of Object.entries(parsed).slice(0, 120)) {
      const next = location ? `${location}.${key}` : key;
      if (regex.test(key) || regex.test(next)) {
        out.push({ field: next, valuePreview: toPreview(item, 500) });
      }
      collectMatchingFields(item, regex, next, out, depth + 1);
    }
  }

  return out;
}

function flatten(value: unknown, prefix = "", out: JsonObject = {}, depth = 0): JsonObject {
  const parsed = tryParseJson(value);
  if (depth > 5) {
    out[prefix || "value"] = "[max-depth]";
    return out;
  }

  if (Array.isArray(parsed)) {
    parsed.slice(0, 20).forEach((item, index) => flatten(item, `${prefix}[${index}]`, out, depth + 1));
    return out;
  }

  if (isRecord(parsed)) {
    for (const [key, item] of Object.entries(parsed).slice(0, 100)) {
      flatten(item, prefix ? `${prefix}.${key}` : key, out, depth + 1);
    }
    return out;
  }

  out[prefix || "value"] = parsed as string | number | boolean | null;
  return out;
}

function parseUrlParts(url: string): { path: string; query: JsonObject; hostname: string } {
  try {
    const parsed = new URL(url, "https://wmpf.local");
    const query: JsonObject = {};
    for (const [key, value] of parsed.searchParams.entries()) {
      if (query[key] === undefined) {
        query[key] = value;
      } else if (Array.isArray(query[key])) {
        (query[key] as string[]).push(value);
      } else {
        query[key] = [query[key], value];
      }
    }
    return { path: parsed.pathname, query, hostname: parsed.hostname };
  } catch {
    return { path: url, query: {}, hostname: "" };
  }
}

function normalizeHeaders(value: unknown): JsonObject {
  if (!isRecord(value)) {
    return {};
  }

  return value;
}

function normalizeMethod(value: unknown): string {
  return String(value || "GET").toUpperCase();
}

function buildCdpRequests(): NormalizedRequest[] {
  const grouped = new Map<string, NormalizedRequest>();

  for (const event of cdp.getRecentRequests(300)) {
    const params = event.params as JsonObject;
    const requestId = String(params.requestId ?? params.loaderId ?? crypto.randomUUID());
    const existing = grouped.get(requestId);
    const base: NormalizedRequest =
      existing ??
      {
        id: `cdp:${requestId}`,
        cdpRequestId: requestId,
        source: "cdp",
        method: "GET",
        url: "",
        path: "",
        query: {},
        requestHeaders: {},
        requestBodyPreview: undefined,
        responseHeaders: {},
        timestamp: event.timestamp,
        raw: []
      };

    if (Array.isArray(base.raw)) {
      base.raw.push(event);
    }

    if (event.method === "Network.requestWillBeSent") {
      const request = params.request as JsonObject | undefined;
      const url = String(request?.url ?? base.url ?? "");
      const parsed = parseUrlParts(url);
      base.url = url;
      base.path = parsed.path;
      base.query = parsed.query;
      base.method = normalizeMethod(request?.method);
      base.requestHeaders = sanitizeSensitive(normalizeHeaders(request?.headers)) as JsonObject;
      base.requestBodyRaw = request?.postData;
      base.requestBodyPreview = toPreview(request?.postData);
      base.timestamp = event.timestamp;
    }

    if (event.method === "Network.responseReceived") {
      const response = params.response as JsonObject | undefined;
      const url = String(response?.url ?? base.url ?? "");
      const parsed = parseUrlParts(url);
      base.url = base.url || url;
      base.path = base.path || parsed.path;
      base.query = Object.keys(base.query).length ? base.query : parsed.query;
      base.statusCode = typeof response?.status === "number" ? response.status : base.statusCode;
      base.responseHeaders = sanitizeSensitive(normalizeHeaders(response?.headers)) as JsonObject;
    }

    if (event.method === "Network.loadingFinished" && typeof params.encodedDataLength === "number") {
      base.responseBodyPreview ??= `[${params.encodedDataLength} encoded bytes; call get_request_detail for body if supported]`;
    }

    grouped.set(requestId, base);
  }

  return [...grouped.values()].filter(req => req.url || req.path);
}

async function getHookArray(globalName: string, preferAppservice = false): Promise<JsonObject[]> {
  if (!cdp.isConnected()) {
    return [];
  }

  if (preferAppservice) {
    try {
      const value = await evalInAppservice<unknown>(`(() => Array.isArray(globalThis.${globalName}) ? globalThis.${globalName}.slice(-300) : [])()`);
      if (Array.isArray(value)) {
        return value.filter(isRecord) as JsonObject[];
      }
    } catch {
      // Fall back to the default page context below.
    }
  }

  try {
    const value = await evalJson<unknown>(`(() => Array.isArray(globalThis.${globalName}) ? globalThis.${globalName}.slice(-300) : [])()`);
    return Array.isArray(value) ? (value.filter(isRecord) as JsonObject[]) : [];
  } catch {
    return [];
  }
}

function normalizeWxRequest(item: JsonObject): NormalizedRequest {
  const url = String(item.url ?? "");
  const parsed = parseUrlParts(url);
  return {
    id: String(item.id ?? `wx:${crypto.randomUUID()}`),
    source: "wx",
    method: normalizeMethod(item.method),
    url,
    path: parsed.path,
    query: parsed.query,
    requestHeaders: sanitizeSensitive(normalizeHeaders(item.header)) as JsonObject,
    requestBodyRaw: item.data,
    requestBodyPreview: toPreview(item.data ?? item.dataPreview),
    statusCode: typeof item.statusCode === "number" ? item.statusCode : undefined,
    responseHeaders: sanitizeSensitive(normalizeHeaders(item.responseHeader)) as JsonObject,
    responseBodyRaw: item.responseData,
    responseBodyPreview: toPreview(item.responseData ?? item.responseDataPreview),
    durationMs: typeof item.durationMs === "number" ? item.durationMs : undefined,
    timestamp: String(item.timestamp ?? ""),
    callStack: typeof item.callStack === "string" ? item.callStack : undefined,
    raw: sanitizeSensitive(item)
  };
}

function normalizeHttpRequest(item: JsonObject): NormalizedRequest {
  const source: RequestSource = item.source === "xhr" ? "xhr" : "fetch";
  const url = String(item.url ?? "");
  const parsed = parseUrlParts(url);
  return {
    id: String(item.id ?? `${source}:${crypto.randomUUID()}`),
    source,
    method: normalizeMethod(item.method),
    url,
    path: parsed.path,
    query: parsed.query,
    requestHeaders: sanitizeSensitive(normalizeHeaders(item.headers)) as JsonObject,
    requestBodyRaw: item.body,
    requestBodyPreview: toPreview(item.body),
    statusCode: typeof item.statusCode === "number" ? item.statusCode : undefined,
    responseHeaders: sanitizeSensitive(normalizeHeaders(item.responseHeaders)) as JsonObject,
    responseBodyRaw: item.responseBody,
    responseBodyPreview: toPreview(item.responseBody ?? item.responseBodyPreview),
    durationMs: typeof item.durationMs === "number" ? item.durationMs : undefined,
    timestamp: String(item.timestamp ?? item.time ?? ""),
    callStack: typeof item.callStack === "string" ? item.callStack : undefined,
    raw: sanitizeSensitive(item)
  };
}

function filterRequests(requests: NormalizedRequest[], filters: RequestFilters): NormalizedRequest[] {
  const keyword = filters.keyword?.toLowerCase();
  const domain = filters.domain?.toLowerCase();
  const pathPrefix = filters.pathPrefix?.toLowerCase();
  const limit = clampLimit(filters.limit, 50, 500);

  return requests
    .filter(req => {
      if (keyword && !JSON.stringify(req).toLowerCase().includes(keyword)) {
        return false;
      }

      if (domain) {
        const host = parseUrlParts(req.url).hostname.toLowerCase();
        if (!host.includes(domain)) {
          return false;
        }
      }

      if (pathPrefix && !req.path.toLowerCase().startsWith(pathPrefix)) {
        return false;
      }

      return true;
    })
    .slice(-limit);
}

function isStaticNoiseRequest(req: NormalizedRequest): boolean {
  const url = req.url.toLowerCase();
  const headers = JSON.stringify(req.responseHeaders).toLowerCase();
  return (
    url.startsWith("data:") ||
    /\.(png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|map)(\?|#|$)/i.test(url) ||
    /image\/|font\/|application\/font|octet-stream/.test(headers)
  );
}

function compactRequest(req: NormalizedRequest): JsonObject {
  return {
    id: req.id,
    source: req.source,
    method: req.method,
    url: req.url,
    path: req.path,
    query: sanitizeSensitive(req.query),
    statusCode: req.statusCode,
    requestHeaders: sanitizeSensitive(req.requestHeaders),
    requestBodyPreview: toPreview(req.requestBodyRaw ?? req.requestBodyPreview, 2_000),
    responseHeaders: sanitizeSensitive(req.responseHeaders),
    responseBodyPreview: toPreview(req.responseBodyRaw ?? req.responseBodyPreview, 2_000),
    durationMs: req.durationMs,
    timestamp: req.timestamp,
    cdpRequestId: req.cdpRequestId
  };
}

async function getAllRequestsInternal(filters: RequestFilters = {}): Promise<NormalizedRequest[]> {
  const wxRequests = (await getHookArray("__WMPF_MCP_WX_REQUESTS__", true)).map(normalizeWxRequest);
  const httpRequests = (await getHookArray("__WMPF_MCP_HTTP_REQUESTS__")).map(normalizeHttpRequest);
  const legacyRequests = (await getHookArray("__WMPF_MCP_REQUESTS__")).map(normalizeHttpRequest);
  const all = [...buildCdpRequests(), ...wxRequests, ...httpRequests, ...legacyRequests].sort((a, b) =>
    String(a.timestamp ?? "").localeCompare(String(b.timestamp ?? ""))
  );

  return filterRequests(all, filters);
}

function getRequestById(requests: NormalizedRequest[], requestId: string): NormalizedRequest | undefined {
  return requests.find(req => req.id === requestId || req.cdpRequestId === requestId);
}

function authIndicators(req: NormalizedRequest): string[] {
  const fields = [
    ...Object.keys(req.requestHeaders),
    ...Object.keys(req.query),
    ...[...collectFieldKeys(req.requestBodyRaw)],
    ...[...collectFieldKeys(req.requestBodyPreview)]
  ];

  return [...new Set(fields.filter(field => AUTH_FIELD_REGEX.test(field)))];
}

function sensitiveFields(req: NormalizedRequest): string[] {
  const fields = [
    ...Object.keys(req.query),
    ...Object.keys(req.requestHeaders),
    ...Object.keys(req.responseHeaders),
    ...[...collectFieldKeys(req.requestBodyRaw)],
    ...[...collectFieldKeys(req.responseBodyRaw)],
    ...[...collectFieldKeys(req.responseBodyPreview)]
  ];

  return [...new Set(fields.filter(field => SENSITIVE_FIELD_REGEX.test(field)))];
}

function idLikeParams(req: NormalizedRequest): string[] {
  const fields = [
    ...Object.keys(req.query),
    ...[...collectFieldKeys(req.requestBodyRaw)],
    ...[...collectFieldKeys(req.requestBodyPreview)],
    ...[...collectFieldKeys(req.responseBodyRaw)],
    ...[...collectFieldKeys(req.responseBodyPreview)]
  ];

  return [...new Set(fields.filter(field => ID_FIELD_REGEX.test(field)))];
}

function riskTags(req: NormalizedRequest): string[] {
  const text = JSON.stringify(req).toLowerCase();
  const tags = new Set<string>();

  const addByNeedle = (tag: string, needles: string[]) => {
    if (needles.some(needle => text.includes(needle))) {
      tags.add(tag);
    }
  };

  addByNeedle("auth", ["auth", "token", "session", "login", "openid", "unionid"]);
  addByNeedle("login", ["login", "signin", "oauth", "passport", "session"]);
  addByNeedle("user_info", ["user", "member", "profile", "phone", "mobile", "realname"]);
  addByNeedle("order", ["order", "trade", "invoice"]);
  addByNeedle("payment", ["pay", "payment", "wallet", "balance", "refund", "withdraw"]);
  addByNeedle("coupon", ["coupon", "voucher", "discount"]);
  addByNeedle("wallet", ["wallet", "balance", "point", "coin"]);
  addByNeedle("address", ["address", "receiver", "shipping"]);
  addByNeedle("upload", ["upload", "avatar", "media"]);
  addByNeedle("file", ["file", "image", "multipart", "download"]);
  addByNeedle("admin", ["admin", "manager", "backend"]);
  addByNeedle("debug", ["debug", "test", "internal", "dev", "staging", "mock"]);

  if (idLikeParams(req).length > 0) {
    tags.add("idor_candidate");
  }

  if (req.method !== "GET" && collectFieldKeys(req.requestBodyRaw).size > 5) {
    tags.add("mass_assignment_candidate");
  }

  if (sensitiveFields(req).length > 0) {
    tags.add("sensitive_data");
  }

  if (authIndicators(req).length === 0 && /user|order|pay|wallet|address|coupon/.test(text)) {
    tags.add("weak_auth_indicator");
  }

  if (/sign|signature|timestamp|nonce/.test(text)) {
    tags.add("replay_candidate");
  }

  return [...tags];
}

function summarizeInventory(requests: NormalizedRequest[]) {
  const groups = new Map<string, {
    method: string;
    path: string;
    exampleUrl: string;
    statusCodes: Set<number>;
    requestParamKeys: Set<string>;
    responseFieldKeys: Set<string>;
    authIndicators: Set<string>;
    idLikeParams: Set<string>;
    sensitiveFields: Set<string>;
    riskTags: Set<string>;
    evidenceRequestIds: string[];
  }>();

  for (const req of requests) {
    const key = `${req.method} ${req.path}`;
    const group =
      groups.get(key) ??
      {
        method: req.method,
        path: req.path,
        exampleUrl: req.url,
        statusCodes: new Set<number>(),
        requestParamKeys: new Set<string>(),
        responseFieldKeys: new Set<string>(),
        authIndicators: new Set<string>(),
        idLikeParams: new Set<string>(),
        sensitiveFields: new Set<string>(),
        riskTags: new Set<string>(),
        evidenceRequestIds: []
      };

    if (typeof req.statusCode === "number") {
      group.statusCodes.add(req.statusCode);
    }
    Object.keys(req.query).forEach(keyName => group.requestParamKeys.add(`query.${keyName}`));
    collectFieldKeys(req.requestBodyRaw).forEach(keyName => group.requestParamKeys.add(`body.${keyName}`));
    collectFieldKeys(req.responseBodyRaw ?? req.responseBodyPreview).forEach(keyName => group.responseFieldKeys.add(keyName));
    authIndicators(req).forEach(value => group.authIndicators.add(value));
    idLikeParams(req).forEach(value => group.idLikeParams.add(value));
    sensitiveFields(req).forEach(value => group.sensitiveFields.add(value));
    riskTags(req).forEach(value => group.riskTags.add(value));
    if (!group.evidenceRequestIds.includes(req.id)) {
      group.evidenceRequestIds.push(req.id);
    }
    groups.set(key, group);
  }

  return [...groups.values()].map(group => ({
    method: group.method,
    path: group.path,
    exampleUrl: group.exampleUrl,
    statusCodes: [...group.statusCodes],
    requestParamKeys: [...group.requestParamKeys].slice(0, 80),
    responseFieldKeys: [...group.responseFieldKeys].slice(0, 80),
    authIndicators: [...group.authIndicators],
    idLikeParams: [...group.idLikeParams],
    sensitiveFields: [...group.sensitiveFields],
    riskTags: [...group.riskTags],
    evidenceRequestIds: group.evidenceRequestIds.slice(0, 10)
  }));
}

function runtimeSnapshotExpression(maxLength: number): string {
  return `(() => {
    const maxLength = ${maxLength};
    const cut = value => String(value ?? "").slice(0, maxLength);
    const cssPath = el => {
      if (!el) return null;
      if (el.id && globalThis.CSS?.escape) return "#" + CSS.escape(el.id);
      const parts = [];
      let node = el;
      while (node && node.nodeType === 1 && parts.length < 5) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;
        if (!parent) { parts.unshift(tag); break; }
        const index = Array.from(parent.children).filter(child => child.tagName === node.tagName).indexOf(node) + 1;
        parts.unshift(tag + ":nth-of-type(" + index + ")");
        node = parent;
      }
      return parts.join(" > ");
    };
    const isVisible = el => {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const storageDump = storage => {
      try {
        const result = {};
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          result[key] = cut(storage.getItem(key));
        }
        return result;
      } catch (e) {
        return { error: String(e) };
      }
    };
    const risk = text => {
      const value = String(text ?? "").toLowerCase();
      const hints = [];
      if (/login|登录|手机号|验证码/.test(value)) hints.push("login");
      if (/pay|支付|付款|钱包|余额/.test(value)) hints.push("payment");
      if (/order|订单/.test(value)) hints.push("order");
      if (/coupon|优惠|券/.test(value)) hints.push("coupon");
      if (/upload|上传|头像|图片/.test(value)) hints.push("upload");
      if (/user|member|个人|用户/.test(value)) hints.push("user_info");
      if (/address|地址|收货/.test(value)) hints.push("address");
      if (/search|搜索|查询/.test(value)) hints.push("search");
      if (/submit|提交|确认/.test(value)) hints.push("submit");
      return hints;
    };
    const interactive = Array.from(document.querySelectorAll('button,input,textarea,select,a,[role="button"],[class*="btn"],[class*="button"],[class*="click"],[class*="submit"],[class*="login"],[class*="pay"],[class*="order"],[class*="user"],[class*="coupon"],[class*="address"],[class*="upload"],[id*="btn"],[id*="button"],[id*="click"],[id*="submit"],[id*="login"],[id*="pay"],[id*="order"],[id*="user"],[id*="coupon"],[id*="address"],[id*="upload"]'))
      .slice(0, 80)
      .map(el => ({
        selector: cssPath(el),
        tag: el.tagName.toLowerCase(),
        text: cut(el.innerText || el.textContent || ""),
        placeholder: el.getAttribute("placeholder"),
        id: el.id || null,
        className: String(el.className || ""),
        disabled: Boolean(el.disabled),
        visible: isVisible(el),
        riskHint: risk([el.innerText, el.textContent, el.id, el.className, el.getAttribute("placeholder")].join(" "))
      }));
    const windowKeys = Object.keys(globalThis).filter(key => /wx|app|route|store|redux|vue|pinia|mobx|config|api|request|token|user|member/i.test(key)).slice(0, 120);
    return {
      location: { href: location.href },
      title: document.title,
      readyState: document.readyState,
      cookie: document.cookie,
      navigator: { userAgent: navigator.userAgent },
      viewport: { innerWidth, innerHeight },
      storage: {
        localStorage: storageDump(localStorage),
        sessionStorage: storageDump(sessionStorage)
      },
      visibleTextSummary: cut(document.body?.innerText || ""),
      interactiveElements: interactive,
      suspiciousWindowKeys: windowKeys
    };
  })()`;
}

function interactiveElementsExpression(): string {
  return `(() => {
    const cut = value => String(value ?? "").slice(0, 1500);
    const cssPath = el => {
      if (!el) return null;
      if (el.id && globalThis.CSS?.escape) return "#" + CSS.escape(el.id);
      const parts = [];
      let node = el;
      while (node && node.nodeType === 1 && parts.length < 5) {
        const tag = node.tagName.toLowerCase();
        const parent = node.parentElement;
        if (!parent) { parts.unshift(tag); break; }
        const index = Array.from(parent.children).filter(child => child.tagName === node.tagName).indexOf(node) + 1;
        parts.unshift(tag + ":nth-of-type(" + index + ")");
        node = parent;
      }
      return parts.join(" > ");
    };
    const isVisible = el => {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    const risk = text => {
      const value = String(text ?? "").toLowerCase();
      const hints = [];
      if (/login|登录|手机号|验证码/.test(value)) hints.push("login");
      if (/pay|支付|付款|钱包|余额/.test(value)) hints.push("payment");
      if (/order|订单/.test(value)) hints.push("order");
      if (/coupon|优惠|券/.test(value)) hints.push("coupon");
      if (/upload|上传|头像|图片/.test(value)) hints.push("upload");
      if (/user|member|个人|用户/.test(value)) hints.push("user_info");
      if (/address|地址|收货/.test(value)) hints.push("address");
      if (/search|搜索|查询/.test(value)) hints.push("search");
      if (/submit|提交|确认/.test(value)) hints.push("submit");
      return hints;
    };
    const selector = 'button,input,textarea,select,a,[role="button"],[class*="btn"],[class*="button"],[class*="click"],[class*="submit"],[class*="login"],[class*="pay"],[class*="order"],[class*="user"],[class*="coupon"],[class*="address"],[class*="upload"],[id*="btn"],[id*="button"],[id*="click"],[id*="submit"],[id*="login"],[id*="pay"],[id*="order"],[id*="user"],[id*="coupon"],[id*="address"],[id*="upload"]';
    const elements = Array.from(document.querySelectorAll(selector)).slice(0, 200).map(el => ({
      selector: cssPath(el),
      tag: el.tagName.toLowerCase(),
      text: cut(el.innerText || el.textContent || ""),
      placeholder: el.getAttribute("placeholder"),
      valuePreview: "value" in el ? cut(el.value) : null,
      id: el.id || null,
      className: String(el.className || ""),
      disabled: Boolean(el.disabled),
      visible: isVisible(el),
      riskHint: risk([el.innerText, el.textContent, el.id, el.className, el.getAttribute("placeholder"), "value" in el ? el.value : ""].join(" "))
    }));
    return { ok: true, count: elements.length, elements };
  })()`;
}

function pageStateExpression(maxLength = 8_000): string {
  return `(() => {
    const dumpStorage = storage => {
      try {
        const out = {};
        for (let i = 0; i < storage.length; i++) {
          const key = storage.key(i);
          out[key] = String(storage.getItem(key) ?? "").slice(0, 1000);
        }
        return out;
      } catch (e) {
        return { error: String(e) };
      }
    };
    return {
      href: location.href,
      title: document.title,
      text: String(document.body?.innerText ?? "").slice(0, ${maxLength}),
      localStorage: dumpStorage(localStorage),
      sessionStorage: dumpStorage(sessionStorage)
    };
  })()`;
}

function safeClickExpression(selector: string, waitMs: number, captureBeforeAfter: boolean, requireConfirm: boolean): string {
  return `(async () => {
    const selector = ${js(selector)};
    const waitMs = ${waitMs};
    const capture = ${captureBeforeAfter};
    const requireConfirm = ${requireConfirm};
    const state = () => (${pageStateExpression(6_000)});
    const el = document.querySelector(selector);
    if (!el) return { ok: false, skipped: true, error: "Element not found", selector };
    const text = [el.innerText, el.textContent, el.value, el.id, el.className, el.getAttribute("aria-label")].join(" ");
    if (${DANGEROUS_CLICK_REGEX.toString()}.test(text) && !requireConfirm) {
      return { ok: false, skipped: true, reason: "dangerous_click_requires_confirm", selector, text: String(text).slice(0, 500) };
    }
    const before = capture ? state() : null;
    el.scrollIntoView?.({ block: "center", inline: "center" });
    el.click();
    await new Promise(resolve => setTimeout(resolve, waitMs));
    const after = capture ? state() : null;
    return {
      ok: true,
      selector,
      clickedText: String(text).slice(0, 500),
      before,
      after,
      urlChanged: before && after ? before.href !== after.href : null,
      textChanged: before && after ? before.text !== after.text : null,
      storageChanged: before && after ? JSON.stringify(before.localStorage) !== JSON.stringify(after.localStorage) || JSON.stringify(before.sessionStorage) !== JSON.stringify(after.sessionStorage) : null
    };
  })()`;
}

function inputTextExpression(selector: string, text: string, waitMs: number): string {
  return `(async () => {
    const selector = ${js(selector)};
    const text = ${js(text)};
    const waitMs = ${waitMs};
    const state = () => (${pageStateExpression(6_000)});
    const el = document.querySelector(selector);
    if (!el) return { ok: false, error: "Element not found", selector };
    const before = state();
    el.focus?.();
    el.value = text;
    for (const type of ["compositionstart", "input", "compositionend", "change"]) {
      el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
    }
    await new Promise(resolve => setTimeout(resolve, waitMs));
    const after = state();
    return {
      ok: true,
      selector,
      before,
      after,
      urlChanged: before.href !== after.href,
      textChanged: before.text !== after.text,
      storageChanged: JSON.stringify(before.localStorage) !== JSON.stringify(after.localStorage) || JSON.stringify(before.sessionStorage) !== JSON.stringify(after.sessionStorage)
    };
  })()`;
}

function hookWxRequestExpression(): string {
  return `(() => {
    if (globalThis.__WMPF_MCP_WX_HOOKED__) {
      return { ok: true, alreadyHooked: true, count: globalThis.__WMPF_MCP_WX_REQUESTS__?.length ?? 0 };
    }
    const wxObj = globalThis.wx || globalThis.__wxAppCode__?.wx;
    if (!wxObj || typeof wxObj.request !== "function") {
      return { ok: false, error: "wx.request not found in current runtime" };
    }
    const requests = globalThis.__WMPF_MCP_WX_REQUESTS__ = globalThis.__WMPF_MCP_WX_REQUESTS__ || [];
    const trim = value => {
      if (value == null) return null;
      try {
        const text = typeof value === "string" ? value : JSON.stringify(value);
        return text.length > 4000 ? text.slice(0, 4000) + "...[truncated]" : text;
      } catch {
        const text = String(value);
        return text.length > 4000 ? text.slice(0, 4000) + "...[truncated]" : text;
      }
    };
    const clone = value => {
      try { return JSON.parse(JSON.stringify(value)); } catch { return trim(value); }
    };
    const push = item => {
      requests.push(item);
      if (requests.length > 300) requests.splice(0, requests.length - 300);
    };
    const original = wxObj.request;
    wxObj.request = function(options = {}) {
      const id = "wx:" + Date.now() + ":" + Math.random().toString(16).slice(2);
      const startedAt = performance.now();
      const item = {
        id,
        timestamp: new Date().toISOString(),
        url: options.url,
        method: options.method || "GET",
        header: clone(options.header || {}),
        data: clone(options.data),
        dataPreview: trim(options.data),
        callStack: new Error().stack
      };
      let pushed = false;
      const finalize = extra => {
        Object.assign(item, extra, { durationMs: Math.round(performance.now() - startedAt) });
        if (!pushed) {
          pushed = true;
          push(item);
        }
      };
      const wrapped = { ...options };
      const success = options.success;
      const fail = options.fail;
      const complete = options.complete;
      wrapped.success = function(res) {
        finalize({
          statusCode: res?.statusCode,
          responseHeader: clone(res?.header || {}),
          responseData: clone(res?.data),
          responseDataPreview: trim(res?.data),
          errMsg: res?.errMsg
        });
        return typeof success === "function" ? success.apply(this, arguments) : undefined;
      };
      wrapped.fail = function(err) {
        finalize({ errMsg: err?.errMsg || String(err), error: clone(err) });
        return typeof fail === "function" ? fail.apply(this, arguments) : undefined;
      };
      wrapped.complete = function(res) {
        if (!pushed && res) finalize({ errMsg: res?.errMsg, completeResultPreview: trim(res) });
        return typeof complete === "function" ? complete.apply(this, arguments) : undefined;
      };
      return original.call(this, wrapped);
    };
    globalThis.__WMPF_MCP_WX_HOOKED__ = true;
    return { ok: true, alreadyHooked: false, count: requests.length };
  })()`;
}

function hookFetchXhrExpression(): string {
  return `(() => {
    if (globalThis.__WMPF_MCP_HTTP_HOOKED__) {
      return { ok: true, alreadyHooked: true, count: globalThis.__WMPF_MCP_HTTP_REQUESTS__?.length ?? 0 };
    }
    const requests = globalThis.__WMPF_MCP_HTTP_REQUESTS__ = globalThis.__WMPF_MCP_HTTP_REQUESTS__ || [];
    const trim = value => {
      if (value == null) return null;
      try {
        const text = typeof value === "string" ? value : JSON.stringify(value);
        return text.length > 4000 ? text.slice(0, 4000) + "...[truncated]" : text;
      } catch {
        const text = String(value);
        return text.length > 4000 ? text.slice(0, 4000) + "...[truncated]" : text;
      }
    };
    const headersToObject = headers => {
      try {
        if (!headers) return {};
        if (headers instanceof Headers) return Object.fromEntries(headers.entries());
        if (Array.isArray(headers)) return Object.fromEntries(headers);
        if (typeof headers === "string") {
          return Object.fromEntries(headers.trim().split(/\\r?\\n/).filter(Boolean).map(line => {
            const index = line.indexOf(":");
            return index > -1 ? [line.slice(0, index).trim(), line.slice(index + 1).trim()] : [line, ""];
          }));
        }
        return { ...headers };
      } catch (e) {
        return { error: String(e) };
      }
    };
    const push = item => {
      requests.push(item);
      globalThis.__WMPF_MCP_REQUESTS__ = requests;
      if (requests.length > 300) requests.splice(0, requests.length - 300);
    };
    if (typeof globalThis.fetch === "function") {
      const originalFetch = globalThis.fetch;
      globalThis.fetch = function(input, init = {}) {
        const id = "fetch:" + Date.now() + ":" + Math.random().toString(16).slice(2);
        const startedAt = performance.now();
        const url = typeof input === "string" ? input : input?.url;
        const method = init?.method || (typeof input !== "string" ? input?.method : undefined) || "GET";
        const item = {
          id,
          source: "fetch",
          timestamp: new Date().toISOString(),
          url,
          method,
          headers: headersToObject(init?.headers || (typeof input !== "string" ? input?.headers : undefined)),
          body: trim(init?.body),
          callStack: new Error().stack
        };
        return originalFetch.apply(this, arguments).then(response => {
          item.statusCode = response.status;
          item.responseHeaders = headersToObject(response.headers);
          item.durationMs = Math.round(performance.now() - startedAt);
          try {
            response.clone().text().then(text => {
              item.responseBody = trim(text);
              push(item);
            }).catch(err => {
              item.responseBodyError = String(err);
              push(item);
            });
          } catch (e) {
            item.responseBodyError = String(e);
            push(item);
          }
          return response;
        }, error => {
          item.errMsg = String(error);
          item.durationMs = Math.round(performance.now() - startedAt);
          push(item);
          throw error;
        });
      };
    }
    if (typeof globalThis.XMLHttpRequest === "function") {
      const proto = globalThis.XMLHttpRequest.prototype;
      const originalOpen = proto.open;
      const originalSetHeader = proto.setRequestHeader;
      const originalSend = proto.send;
      proto.open = function(method, url) {
        this.__wmpfMcp = { id: "xhr:" + Date.now() + ":" + Math.random().toString(16).slice(2), source: "xhr", timestamp: new Date().toISOString(), method, url, headers: {}, callStack: new Error().stack };
        return originalOpen.apply(this, arguments);
      };
      proto.setRequestHeader = function(name, value) {
        if (this.__wmpfMcp) this.__wmpfMcp.headers[name] = value;
        return originalSetHeader.apply(this, arguments);
      };
      proto.send = function(body) {
        const item = this.__wmpfMcp || { id: "xhr:" + Date.now(), source: "xhr", timestamp: new Date().toISOString(), headers: {}, callStack: new Error().stack };
        const startedAt = performance.now();
        item.body = trim(body);
        const finalize = () => {
          item.statusCode = this.status;
          item.responseHeaders = headersToObject(this.getAllResponseHeaders?.() || "");
          item.responseBody = trim(this.responseText ?? this.response);
          item.durationMs = Math.round(performance.now() - startedAt);
          push(item);
        };
        this.addEventListener("loadend", finalize, { once: true });
        this.addEventListener("error", () => { item.errMsg = "xhr_error"; finalize(); }, { once: true });
        return originalSend.apply(this, arguments);
      };
    }
    globalThis.__WMPF_MCP_HTTP_HOOKED__ = true;
    return { ok: true, alreadyHooked: false, count: requests.length };
  })()`;
}

function inspectWxConfigExpression(maxLength: number): string {
  return `(() => {
    const maxLength = ${maxLength};
    const names = ["__wxConfig", "__wxAppCode__", "__wxRoute", "__wxAppData__"];
    const keywords = ${js(DEFAULT_KEYWORDS)};
    const cut = value => {
      try {
        const text = typeof value === "string" ? value : JSON.stringify(value);
        return String(text ?? "").slice(0, maxLength);
      } catch (e) {
        return String(value).slice(0, maxLength);
      }
    };
    const out = {};
    for (const name of names) {
      const value = globalThis[name];
      const text = cut(value);
      out[name] = {
        exists: value !== undefined,
        type: typeof value,
        keys: value && typeof value === "object" ? Object.keys(value).slice(0, 80) : [],
        preview: text,
        keywordHits: keywords.filter(keyword => text.toLowerCase().includes(keyword.toLowerCase()))
      };
    }
    return { ok: true, summary: out };
  })()`;
}

function searchRuntimeKeywordsExpression(keywords: string[], maxLength: number): string {
  return `(async () => {
    const keywords = ${js(keywords)};
    const maxLength = ${maxLength};
    const contextSize = 180;
    const hits = [];
    const addHits = (source, text) => {
      const value = String(text ?? "");
      const lower = value.toLowerCase();
      for (const keyword of keywords) {
        const index = lower.indexOf(String(keyword).toLowerCase());
        if (index >= 0) {
          hits.push({
            source,
            keyword,
            index,
            context: value.slice(Math.max(0, index - contextSize), Math.min(value.length, index + String(keyword).length + contextSize))
          });
        }
      }
    };
    addHits("window.keys", Object.keys(globalThis).join("\\n"));
    addHits("document.html", document.documentElement?.outerHTML || "");
    try {
      const storage = {};
      for (const area of ["localStorage", "sessionStorage"]) {
        storage[area] = {};
        const s = globalThis[area];
        for (let i = 0; i < s.length; i++) {
          const key = s.key(i);
          storage[area][key] = s.getItem(key);
        }
      }
      addHits("storage", JSON.stringify(storage));
    } catch (e) {
      hits.push({ source: "storage", error: String(e) });
    }
    const scripts = Array.from(document.scripts || []);
    for (let i = 0; i < scripts.length; i++) {
      const script = scripts[i];
      if (script.textContent) addHits("script.inline[" + i + "]", script.textContent);
      if (JSON.stringify(hits).length > maxLength) break;
    }
    const returned = [];
    let size = 0;
    for (const hit of hits) {
      const length = JSON.stringify(hit).length;
      if (size + length > maxLength) break;
      returned.push(hit);
      size += length;
    }
    return { ok: true, keywords, hitCount: hits.length, returnedCount: returned.length, truncated: returned.length < hits.length, hits: returned };
  })()`;
}

function inspectVuexStoreExpression(maxLength: number): string {
  return `(() => {
    const maxLength = ${maxLength};
    const cut = value => {
      try {
        const text = typeof value === "string" ? value : JSON.stringify(value);
        return String(text ?? "").slice(0, maxLength);
      } catch (e) {
        return String(value).slice(0, maxLength);
      }
    };
    const clone = value => {
      try { return JSON.parse(JSON.stringify(value)); } catch { return cut(value); }
    };
    const findStore = () => {
      const candidates = [];
      try { if (typeof require === "function") candidates.push({ source: 'require("store/index.js").store', value: require("store/index.js")?.store }); } catch {}
      for (const key of Object.keys(globalThis)) {
        try {
          const value = globalThis[key];
          if (value && typeof value === "object" && value.state && typeof value.commit === "function") {
            candidates.push({ source: "globalThis." + key, value });
          }
          if (value && typeof value === "object" && value.store?.state && typeof value.store?.commit === "function") {
            candidates.push({ source: "globalThis." + key + ".store", value: value.store });
          }
        } catch {}
      }
      return candidates.find(item => item.value && item.value.state && typeof item.value.commit === "function");
    };
    const found = findStore();
    if (!found) return { ok: false, error: "Vuex-like store not found in appservice context" };
    const store = found.value;
    if (!globalThis.__WMPF_MCP_VUEX_SNAPSHOT__) {
      globalThis.__WMPF_MCP_VUEX_SNAPSHOT__ = clone(store.state);
    }
    return {
      ok: true,
      source: found.source,
      statePreview: cut(store.state),
      stateKeys: store.state && typeof store.state === "object" ? Object.keys(store.state).slice(0, 120) : [],
      getters: store.getters && typeof store.getters === "object" ? Object.keys(store.getters).slice(0, 120) : [],
      mutations: store._mutations && typeof store._mutations === "object" ? Object.keys(store._mutations).slice(0, 200) : [],
      actions: store._actions && typeof store._actions === "object" ? Object.keys(store._actions).slice(0, 200) : [],
      snapshotSaved: Boolean(globalThis.__WMPF_MCP_VUEX_SNAPSHOT__)
    };
  })()`;
}

function patchVuexStateExpression(pathValue: string, value: unknown, dryRun: boolean, requireConfirm: boolean, commitType?: string, payload?: unknown): string {
  return `(() => {
    const pathValue = ${js(pathValue)};
    const nextValue = ${js(value)};
    const dryRun = ${dryRun};
    const requireConfirm = ${requireConfirm};
    const commitType = ${commitType ? js(commitType) : "null"};
    const payload = ${payload === undefined ? "undefined" : js(payload)};
    const clone = value => { try { return JSON.parse(JSON.stringify(value)); } catch { return value; } };
    const findStore = () => {
      try { const store = typeof require === "function" ? require("store/index.js")?.store : null; if (store?.state && typeof store.commit === "function") return store; } catch {}
      for (const key of Object.keys(globalThis)) {
        try {
          const value = globalThis[key];
          if (value?.state && typeof value.commit === "function") return value;
          if (value?.store?.state && typeof value.store.commit === "function") return value.store;
        } catch {}
      }
      return null;
    };
    const getByPath = (root, pathText) => pathText.split(".").filter(Boolean).reduce((obj, key) => obj?.[key], root);
    const setByPath = (root, pathText, value) => {
      const parts = pathText.split(".").filter(Boolean);
      const last = parts.pop();
      const parent = parts.reduce((obj, key) => obj?.[key], root);
      if (!parent || !last) throw new Error("Invalid state path: " + pathText);
      parent[last] = value;
    };
    const store = findStore();
    if (!store) return { ok: false, error: "Vuex-like store not found" };
    if (!globalThis.__WMPF_MCP_VUEX_SNAPSHOT__) globalThis.__WMPF_MCP_VUEX_SNAPSHOT__ = clone(store.state);
    const before = commitType ? null : clone(getByPath(store.state, pathValue));
    if (dryRun || !requireConfirm) {
      return { ok: true, dryRun: true, requireConfirm, warning: "No state changed. Set dryRun=false and requireConfirm=true to mutate authorized local runtime state.", sourcePath: pathValue, before, nextValue, commitType, payload };
    }
    if (commitType) {
      store.commit(commitType, payload === undefined ? nextValue : payload);
    } else {
      setByPath(store.state, pathValue, nextValue);
    }
    const after = commitType ? clone(store.state) : clone(getByPath(store.state, pathValue));
    return { ok: true, dryRun: false, sourcePath: pathValue, before, after, commitType, snapshotSaved: Boolean(globalThis.__WMPF_MCP_VUEX_SNAPSHOT__) };
  })()`;
}

function restoreVuexStateExpression(dryRun: boolean, requireConfirm: boolean): string {
  return `(() => {
    const dryRun = ${dryRun};
    const requireConfirm = ${requireConfirm};
    const clone = value => { try { return JSON.parse(JSON.stringify(value)); } catch { return value; } };
    const findStore = () => {
      try { const store = typeof require === "function" ? require("store/index.js")?.store : null; if (store?.state && typeof store.commit === "function") return store; } catch {}
      for (const key of Object.keys(globalThis)) {
        try {
          const value = globalThis[key];
          if (value?.state && typeof value.commit === "function") return value;
          if (value?.store?.state && typeof value.store.commit === "function") return value.store;
        } catch {}
      }
      return null;
    };
    const store = findStore();
    if (!store) return { ok: false, error: "Vuex-like store not found" };
    const snapshot = globalThis.__WMPF_MCP_VUEX_SNAPSHOT__;
    if (!snapshot) return { ok: false, error: "No Vuex snapshot saved. Run inspect_vuex_store first." };
    if (dryRun || !requireConfirm) {
      return { ok: true, dryRun: true, requireConfirm, warning: "No state changed. Set dryRun=false and requireConfirm=true to restore snapshot.", snapshotPreview: clone(snapshot) };
    }
    if (typeof store.replaceState === "function") {
      store.replaceState(clone(snapshot));
    } else {
      Object.keys(store.state).forEach(key => delete store.state[key]);
      Object.assign(store.state, clone(snapshot));
    }
    return { ok: true, dryRun: false, restored: true, statePreview: clone(store.state) };
  })()`;
}

function buildReplayPlan(req: NormalizedRequest) {
  const volatileHeaderRegex = /^(cookie|authorization|x-request-id|trace|referer|origin|host|content-length|accept-encoding|connection)$/i;
  const headers = Object.keys(req.requestHeaders);
  const requestParams = [...Object.keys(req.query), ...collectFieldKeys(req.requestBodyRaw)];
  const candidateParamsToMutate = requestParams.filter(param => ID_FIELD_REGEX.test(param) || /price|amount|count|num|role|status|type|coupon|balance/i.test(param));
  return {
    method: req.method,
    url: req.url,
    headersToKeep: headers.filter(header => !volatileHeaderRegex.test(header)),
    headersToRemove: headers.filter(header => volatileHeaderRegex.test(header)),
    body: toPreview(req.requestBodyRaw ?? req.requestBodyPreview, 8_000),
    candidateParamsToMutate,
    expectedSecurityChecks: [
      "服务端重新校验登录态和用户身份绑定",
      "对象 ID 必须与当前账号/角色授权范围匹配",
      "金额、优惠、库存、积分等关键字段由服务端计算",
      "签名应绑定 path、method、body、用户身份、timestamp、nonce",
      "timestamp 有短窗口限制，nonce 不可重复使用"
    ],
    notes: [
      "此工具只生成计划，不自动发送请求。",
      "需要授权环境中人工验证，可复制到 Burp Repeater 中单次测试。"
    ]
  };
}

function diffObjects(a: unknown, b: unknown): JsonObject[] {
  const flatA = flatten(a);
  const flatB = flatten(b);
  const keys = [...new Set([...Object.keys(flatA), ...Object.keys(flatB)])];
  return keys
    .filter(key => JSON.stringify(flatA[key]) !== JSON.stringify(flatB[key]))
    .slice(0, 200)
    .map(key => ({
      key,
      a: toPreview(flatA[key], 500),
      b: toPreview(flatB[key], 500)
    }));
}

function buildFindings(requests: NormalizedRequest[]) {
  return {
    authSurface: analyzeAuthSurfaceData(requests),
    idorCandidates: findIdorCandidatesData(requests),
    sensitiveDataExposure: findSensitiveDataData(requests),
    uploadSurfaces: findUploadSurfacesData(requests),
    paymentAndOrderSurfaces: findPaymentOrderData(requests),
    debugAdminSurfaces: findDebugAdminData(requests),
    signRelatedRequests: findSignRequestsData(requests)
  };
}

function analyzeAuthSurfaceData(requests: NormalizedRequest[]) {
  const authFieldsFound = new Set<string>();
  const tokenLocations: JsonObject[] = [];
  const tokenInQuery: JsonObject[] = [];
  const missingAuthRequests: JsonObject[] = [];
  const suspiciousAuthPatterns: JsonObject[] = [];
  const replayRiskHints: JsonObject[] = [];

  for (const req of requests) {
    const fields = [
      ...Object.keys(req.requestHeaders).map(field => ({ field, location: "header" })),
      ...Object.keys(req.query).map(field => ({ field, location: "query" })),
      ...collectMatchingFields(req.requestBodyRaw, AUTH_FIELD_REGEX, "body")
    ];
    const authFields = fields.filter(item => AUTH_FIELD_REGEX.test(String(item.field)));
    authFields.forEach(item => {
      authFieldsFound.add(String(item.field));
      tokenLocations.push({ requestId: req.id, path: req.path, field: item.field, location: item.location });
      if (item.location === "query") {
        tokenInQuery.push({ requestId: req.id, path: req.path, field: item.field });
      }
    });

    if (authFields.length === 0 && riskTags(req).some(tag => ["user_info", "order", "payment", "wallet", "address", "coupon"].includes(tag))) {
      missingAuthRequests.push({ requestId: req.id, method: req.method, path: req.path, reason: "业务敏感接口未观察到明显认证字段" });
    }

    if (/token|session|authorization/i.test(JSON.stringify(req.query))) {
      suspiciousAuthPatterns.push({ requestId: req.id, path: req.path, reason: "认证信息出现在 query 中，可能进入日志、Referer 或分享链路" });
    }

    if (/sign|signature|timestamp|nonce/i.test(JSON.stringify(req))) {
      replayRiskHints.push({ requestId: req.id, path: req.path, hint: "存在签名/时间戳/nonce 字段，建议人工验证时间窗口、nonce 一次性和签名绑定范围" });
    }
  }

  return {
    authFields: [...authFieldsFound],
    tokenLocations: tokenLocations.slice(0, 100),
    tokenInQuery: tokenInQuery.slice(0, 100),
    missingAuthRequests: missingAuthRequests.slice(0, 100),
    suspiciousAuthPatterns: suspiciousAuthPatterns.slice(0, 100),
    replayRiskHints: replayRiskHints.slice(0, 100)
  };
}

function findIdorCandidatesData(requests: NormalizedRequest[]) {
  return requests
    .map(req => {
      const fields = [
        ...Object.keys(req.query).filter(field => ID_FIELD_REGEX.test(field)).map(field => `query.${field}`),
        ...collectMatchingFields(req.requestBodyRaw, ID_FIELD_REGEX, "body").map(item => String(item.field)),
        ...collectMatchingFields(req.responseBodyRaw ?? req.responseBodyPreview, ID_FIELD_REGEX, "response").map(item => String(item.field))
      ];
      return {
        requestId: req.id,
        method: req.method,
        path: req.path,
        idFields: [...new Set(fields)],
        reason: "请求或响应中存在对象/用户/订单等 ID 类字段，可能需要授权边界验证",
        suggestedManualChecks: [
          "使用不同账号采集同一路径请求并对比 ID 绑定关系",
          "在 Burp 中单次替换为授权范围外 ID，观察是否被服务端拒绝",
          "确认响应数据是否只返回当前账号可访问对象",
          "检查服务端是否忽略客户端提交的 userId/memberId/uid"
        ]
      };
    })
    .filter(item => item.idFields.length > 0)
    .slice(0, 100);
}

function findSensitiveDataData(requests: NormalizedRequest[]) {
  const findings: JsonObject[] = [];
  for (const req of requests) {
    const areas: Array<[string, unknown]> = [
      ["query", req.query],
      ["requestHeaders", req.requestHeaders],
      ["requestBody", req.requestBodyRaw ?? req.requestBodyPreview],
      ["responseHeaders", req.responseHeaders],
      ["responseBody", req.responseBodyRaw ?? req.responseBodyPreview]
    ];

    for (const [location, value] of areas) {
      for (const match of collectMatchingFields(value, SENSITIVE_FIELD_REGEX, location)) {
        findings.push({
          requestId: req.id,
          field: match.field,
          location,
          maskedPreview: match.valuePreview,
          riskLevel: /idCard|identity|bankCard|session_key|token|authorization|cookie/i.test(String(match.field)) ? "high" : "medium",
          reason: "请求或响应中出现敏感字段，已默认脱敏展示，需要确认最小化返回和传输保护"
        });
      }
    }
  }
  return findings.slice(0, 150);
}

function findUploadSurfacesData(requests: NormalizedRequest[]) {
  return requests
    .filter(req => /upload|file|image|avatar|media|multipart/i.test(JSON.stringify(req)))
    .map(req => ({
      requestId: req.id,
      method: req.method,
      path: req.path,
      contentType: Object.entries(req.requestHeaders).find(([key]) => /content-type/i.test(key))?.[1] ?? null,
      fileFieldHints: [...new Set([...collectFieldKeys(req.requestBodyRaw), ...Object.keys(req.query)].filter(field => /file|image|avatar|media|upload/i.test(field)))],
      suggestedManualChecks: [
        "文件类型校验",
        "文件大小限制",
        "鉴权",
        "存储桶直传",
        "返回 URL 是否可公开访问",
        "覆盖写风险"
      ]
    }))
    .slice(0, 100);
}

function findPaymentOrderData(requests: NormalizedRequest[]) {
  return requests
    .filter(req => /pay|payment|order|coupon|wallet|balance|point|refund|withdraw|price|amount/i.test(JSON.stringify(req)))
    .map(req => {
      const text = JSON.stringify(req).toLowerCase();
      const tags = new Set<string>();
      if (/price|amount|total|fee|pay/.test(text)) tags.add("price_tampering_candidate");
      if (/coupon|voucher|discount/.test(text)) tags.add("coupon_abuse_candidate");
      if (/orderid|order_id|order/.test(text)) tags.add("order_idor_candidate");
      if (/balance|wallet|point|coin|withdraw/.test(text)) tags.add("balance_risk_candidate");
      if (/sign|timestamp|nonce/.test(text)) tags.add("replay_candidate");
      return {
        requestId: req.id,
        method: req.method,
        path: req.path,
        riskTags: [...tags],
        suggestedManualChecks: [
          "只在授权环境中人工验证金额、数量、优惠字段是否由服务端重算",
          "检查订单 ID 是否绑定当前账号",
          "检查优惠券和钱包操作是否有幂等、重放和风控校验",
          "不要自动重放支付或资金类请求"
        ]
      };
    })
    .slice(0, 100);
}

function findDebugAdminData(requests: NormalizedRequest[]) {
  const regex = /debug|test|admin|internal|dev|staging|mock/i;
  return requests
    .filter(req => regex.test(JSON.stringify(req)))
    .map(req => ({
      requestId: req.id,
      method: req.method,
      path: req.path,
      context: truncateString(JSON.stringify(toPreview(req, 3_000)), 3_000)
    }))
    .slice(0, 100);
}

function findSignRequestsData(requests: NormalizedRequest[]) {
  return requests
    .filter(req => /sign|signature|timestamp|nonce/i.test(JSON.stringify(req)))
    .map(req => ({
      requestId: req.id,
      path: req.path,
      signFields: collectMatchingFields(req, /sign|signature/i, "").map(item => item.field),
      timestampFields: collectMatchingFields(req, /timestamp|time/i, "").map(item => item.field),
      nonceFields: collectMatchingFields(req, /nonce|random/i, "").map(item => item.field),
      candidateReplayRisk: true,
      suggestedManualChecks: [
        "时间戳窗口",
        "nonce 是否一次性",
        "sign 是否绑定 body",
        "sign 是否绑定用户身份",
        "sign 是否绑定路径"
      ]
    }))
    .slice(0, 100);
}

function apiTableMarkdown(inventory: ReturnType<typeof summarizeInventory>): string {
  const header = "| 方法 | 路径 | 状态码 | 参数 | 认证 | 敏感字段 | 风险标签 | 证据 requestId |\n|---|---|---|---|---|---|---|---|";
  const rows = inventory.map(item =>
    [
      item.method,
      item.path,
      item.statusCodes.join(", "),
      item.requestParamKeys.slice(0, 12).join("<br>"),
      item.authIndicators.join("<br>"),
      item.sensitiveFields.join("<br>"),
      item.riskTags.join("<br>"),
      item.evidenceRequestIds.join("<br>")
    ]
      .map(value => String(value || "-").replace(/\|/g, "\\|"))
      .join(" | ")
  );

  return [header, ...rows.map(row => `| ${row} |`)].join("\n");
}

function securityNotesMarkdown(pageInfo: unknown, inventory: ReturnType<typeof summarizeInventory>, findings: ReturnType<typeof buildFindings>): string {
  return [
    "# 微信小程序授权安全评估笔记",
    "",
    "## 页面信息",
    "```json",
    JSON.stringify(toPreview(pageInfo, 4_000), null, 2),
    "```",
    "",
    "## 接口清单",
    apiTableMarkdown(inventory),
    "",
    "## 认证字段与重放线索",
    "```json",
    JSON.stringify(findings.authSurface, null, 2),
    "```",
    "",
    "## 敏感信息暴露线索",
    "```json",
    JSON.stringify(findings.sensitiveDataExposure, null, 2),
    "```",
    "",
    "## 越权候选接口",
    "```json",
    JSON.stringify(findings.idorCandidates, null, 2),
    "```",
    "",
    "## 上传接口",
    "```json",
    JSON.stringify(findings.uploadSurfaces, null, 2),
    "```",
    "",
    "## 支付/订单接口",
    "```json",
    JSON.stringify(findings.paymentAndOrderSurfaces, null, 2),
    "```",
    "",
    "## 签名/重放线索",
    "```json",
    JSON.stringify(findings.signRelatedRequests, null, 2),
    "```",
    "",
    "## 待人工验证项",
    "- 所有候选项均为发现线索，不直接下漏洞结论。",
    "- 需要在授权环境中使用不同账号、不同角色或 Burp Repeater 进行单次人工验证。",
    "- 支付、订单、退款、提现等资金类接口不得自动重放。"
  ].join("\n");
}

function registerTools(server: McpServer): void {
  server.registerTool("status", { description: "Return MCP bridge status and CDP connection state.", inputSchema: {} }, async () =>
    safeTool(() => ({
      ok: true,
      mcp: "running",
      cdpConnected: cdp.isConnected(),
      defaultCdpUrl: DEFAULT_CDP_WS_URL,
      recentRequestsCount: cdp.getRecentRequestsCount(),
      recentConsoleCount: cdp.getRecentConsoleCount()
    }))
  );

  server.registerTool("connect_wmpf", { description: "Connect to local WMPFDebugger CDP WebSocket.", inputSchema: { wsUrl: z.string().url().optional().default(DEFAULT_CDP_WS_URL) } }, async ({ wsUrl }) =>
    safeTool(async () => {
      const connection = await cdp.connect(wsUrl);
      selectedAppservice = undefined;
      attachedTargets.clear();
      const runtime = await cdp.enableRuntime().then(result => ({ ok: true, result }), error => ({ ok: false, error: errorMessage(error) }));
      const network = await cdp.enableNetwork().then(result => ({ ok: true, result }), error => ({ ok: false, error: errorMessage(error) }));
      return { ok: true, ...connection, runtime, network };
    })
  );

  server.registerTool("select_appservice_context", { description: "Auto-detect and select the appservice Runtime execution context.", inputSchema: { force: z.boolean().optional().default(false) } }, async ({ force }) =>
    safeTool(async () => ({ ok: true, selected: await selectAppserviceContext(force), targets: await getTargets(), contexts: cdp.getRuntimeContexts() }))
  );

  server.registerTool("cdp_call", { description: "Call an arbitrary CDP method. Supports flatten sessionId.", inputSchema: { method: z.string().min(1), params: z.record(z.unknown()).optional().default({}), sessionId: z.string().optional() } }, async ({ method, params, sessionId }) =>
    safeTool(async () => {
      requireCdpConnected();
      return { ok: true, method, sessionId, result: await cdp.send(method, params, DEFAULT_MAX_LENGTH, sessionId) };
    })
  );

  server.registerTool("cdp_call_target", { description: "Attach to targetId with flatten=true and call a CDP method in that session.", inputSchema: { targetId: z.string().min(1), method: z.string().min(1), params: z.record(z.unknown()).optional().default({}) } }, async ({ targetId, method, params }) =>
    safeTool(async () => {
      requireCdpConnected();
      const sessionId = await attachToTarget(targetId);
      return { ok: true, targetId, sessionId, method, result: await cdp.send(method, params, DEFAULT_MAX_LENGTH, sessionId) };
    })
  );

  server.registerTool("runtime_eval", { description: "Evaluate JavaScript in current runtime.", inputSchema: { expression: z.string().min(1), returnByValue: z.boolean().optional().default(true), awaitPromise: z.boolean().optional().default(true) } }, async ({ expression, returnByValue, awaitPromise }) =>
    safeTool(async () => ({ ok: true, result: await cdp.eval(expression, { returnByValue, awaitPromise }) }))
  );

  server.registerTool("runtime_eval_appservice", { description: "Evaluate JavaScript in the auto-selected appservice context.", inputSchema: { expression: z.string().min(1), forceSelect: z.boolean().optional().default(false) } }, async ({ expression, forceSelect }) =>
    safeTool(async () => {
      const selected = await selectAppserviceContext(forceSelect);
      const result = await cdp.send(
        "Runtime.evaluate",
        { expression, returnByValue: true, awaitPromise: true, contextId: selected.contextId },
        DEFAULT_MAX_LENGTH,
        selected.sessionId
      );
      return { ok: true, selected, result };
    })
  );

  server.registerTool("dump_runtime_snapshot", { description: "Capture page runtime snapshot for security assessment context.", inputSchema: { maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ maxLength }) =>
    safeTool(async () => evalJson(runtimeSnapshotExpression(clampLimit(maxLength, DEFAULT_MAX_LENGTH, 200_000))))
  );

  server.registerTool("get_basic_page_info", { description: "Backward-compatible page info snapshot.", inputSchema: {} }, async () =>
    safeTool(async () => evalJson(runtimeSnapshotExpression(8_000)))
  );

  server.registerTool("get_document_html", { description: "Return document.documentElement.outerHTML prefix.", inputSchema: { maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ maxLength }) =>
    safeTool(async () => {
      const limit = clampLimit(maxLength, DEFAULT_MAX_LENGTH, 500_000);
      const html = await evalJson<string>(`(() => String(document.documentElement?.outerHTML ?? "").slice(0, ${limit}))()`);
      return { ok: true, maxLength: limit, html };
    })
  );

  server.registerTool("query_selector_text", { description: "Return text and HTML snippets for document.querySelector(selector).", inputSchema: { selector: z.string().min(1), maxLength: z.number().int().positive().optional().default(10_000) } }, async ({ selector, maxLength }) =>
    safeTool(async () => {
      const limit = clampLimit(maxLength, 10_000, 200_000);
      return evalJson(`(() => {
        const selector = ${js(selector)};
        const limit = ${limit};
        const el = document.querySelector(selector);
        if (!el) return { ok: false, selector, error: "Element not found" };
        const cut = value => String(value ?? "").slice(0, limit);
        return { ok: true, selector, innerText: cut(el.innerText), textContent: cut(el.textContent), outerHTML: cut(el.outerHTML) };
      })()`);
    })
  );

  server.registerTool("list_interactive_elements", { description: "List clickable/input elements with risk hints.", inputSchema: {} }, async () =>
    safeTool(async () => evalJson(interactiveElementsExpression()))
  );

  server.registerTool("safe_click_and_observe", { description: "Click one element and observe passive deltas. Dangerous texts require requireConfirm=true.", inputSchema: { selector: z.string().min(1), waitMs: z.number().int().positive().optional().default(1_500), captureBeforeAfter: z.boolean().optional().default(true), requireConfirm: z.boolean().optional().default(false) } }, async ({ selector, waitMs, captureBeforeAfter, requireConfirm }) =>
    safeTool(async () => {
      const beforeRequests = cdp.getRecentRequests(300).length;
      const beforeConsole = cdp.getRecentConsole(300).length;
      const result = await evalJson(safeClickExpression(selector, clampLimit(waitMs, 1_500, 10_000), captureBeforeAfter, requireConfirm));
      return {
        ok: true,
        result,
        newCdpRequests: cdp.getRecentRequests(300).slice(beforeRequests),
        newConsole: cdp.getRecentConsole(300).slice(beforeConsole),
        warning: "此工具只点击单个元素；支付/订单/删除/退款/提现等文本默认 requireConfirm=true 才会执行。"
      };
    })
  );

  server.registerTool("input_text_and_observe", { description: "Input text into one field and observe passive deltas.", inputSchema: { selector: z.string().min(1), text: z.string(), waitMs: z.number().int().positive().optional().default(800) } }, async ({ selector, text, waitMs }) =>
    safeTool(async () => {
      const beforeRequests = cdp.getRecentRequests(300).length;
      const beforeConsole = cdp.getRecentConsole(300).length;
      const result = await evalJson(inputTextExpression(selector, text, clampLimit(waitMs, 800, 10_000)));
      return { ok: true, result, newCdpRequests: cdp.getRecentRequests(300).slice(beforeRequests), newConsole: cdp.getRecentConsole(300).slice(beforeConsole) };
    })
  );

  server.registerTool("network_enable", { description: "Enable CDP Network domain.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, result: await cdp.enableNetwork() }))
  );

  server.registerTool("get_recent_requests", { description: "Return recent CDP Network requests with optional filtering and compact output.", inputSchema: { limit: z.number().int().positive().optional().default(50), domain: z.string().optional(), pathPrefix: z.string().optional(), keyword: z.string().optional(), excludeStatic: z.boolean().optional().default(true), compact: z.boolean().optional().default(true) } }, async ({ limit, domain, pathPrefix, keyword, excludeStatic, compact }) =>
    safeTool(() => {
      if (!compact) {
        const events = cdp.getRecentRequests(clampLimit(limit, 50, 300)).filter(event => !keyword || JSON.stringify(event).toLowerCase().includes(keyword.toLowerCase()));
        return { ok: true, compact: false, events };
      }

      let requests = filterRequests(buildCdpRequests(), { limit: 300, domain, pathPrefix, keyword });
      if (excludeStatic) {
        requests = requests.filter(req => !isStaticNoiseRequest(req));
      }
      return { ok: true, compact: true, requests: requests.slice(-clampLimit(limit, 50, 300)).map(compactRequest) };
    })
  );

  server.registerTool("get_response_body", { description: "Return CDP Network.getResponseBody.", inputSchema: { requestId: z.string().min(1) } }, async ({ requestId }) =>
    safeTool(async () => {
      try {
        return { ok: true, requestId, result: await cdp.send("Network.getResponseBody", { requestId }) };
      } catch (error) {
        return { ok: false, requestId, error: errorMessage(error) };
      }
    })
  );

  server.registerTool("get_recent_console", { description: "Return recent console and exception events.", inputSchema: { limit: z.number().int().positive().optional().default(50) } }, async ({ limit }) =>
    safeTool(() => ({ ok: true, events: cdp.getRecentConsole(clampLimit(limit, 50, 300)) }))
  );

  server.registerTool("inspect_window_keys", { description: "List window keys, optionally filtered.", inputSchema: { pattern: z.string().optional(), limit: z.number().int().positive().optional().default(200) } }, async ({ pattern, limit }) =>
    safeTool(async () => evalJson(`(() => {
      const pattern = ${pattern ? js(pattern) : "null"};
      const limit = ${clampLimit(limit, 200, 2_000)};
      const keys = Object.keys(globalThis).sort();
      const filtered = pattern ? keys.filter(key => key.toLowerCase().includes(String(pattern).toLowerCase())) : keys;
      return { ok: true, pattern, count: filtered.length, keys: filtered.slice(0, limit) };
    })()`))
  );

  server.registerTool("search_global_string", { description: "Search document, scripts, window keys for one keyword.", inputSchema: { keyword: z.string().min(1), maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ keyword, maxLength }) =>
    safeTool(async () => evalJson(searchRuntimeKeywordsExpression([keyword], clampLimit(maxLength, DEFAULT_MAX_LENGTH, 200_000))))
  );

  server.registerTool("hook_wx_request", { description: "Inject non-mutating wx.request hook.", inputSchema: {} }, async () =>
    safeTool(async () => {
      const selected = await selectAppserviceContext(false);
      const result = await evalInAppservice(hookWxRequestExpression());
      return { ok: true, selected, result };
    })
  );

  server.registerTool("hook_fetch_and_xhr", { description: "Inject non-mutating fetch/XHR hooks with response capture.", inputSchema: {} }, async () =>
    safeTool(async () => evalJson(hookFetchXhrExpression()))
  );

  server.registerTool("get_hooked_requests", { description: "Return fetch/XHR hook records.", inputSchema: { limit: z.number().int().positive().optional().default(50) } }, async ({ limit }) =>
    safeTool(async () => ({ ok: true, requests: (await getHookArray("__WMPF_MCP_HTTP_REQUESTS__")).slice(-clampLimit(limit, 50, 300)).map(item => sanitizeSensitive(item)) }))
  );

  server.registerTool("get_all_requests", { description: "Return normalized CDP + wx.request + fetch/XHR requests.", inputSchema: { limit: z.number().int().positive().optional().default(50), keyword: z.string().optional(), domain: z.string().optional(), pathPrefix: z.string().optional() } }, async args =>
    safeTool(async () => ({ ok: true, requests: (await getAllRequestsInternal(args)).map(req => sanitizeSensitive(req)) }))
  );

  server.registerTool("get_request_detail", { description: "Return one normalized request and try CDP response body when possible.", inputSchema: { requestId: z.string().min(1), maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ requestId, maxLength }) =>
    safeTool(async () => {
      const req = getRequestById(await getAllRequestsInternal({ limit: 500 }), requestId);
      if (!req) return { ok: false, error: "Request not found", requestId };
      const detail: JsonObject = { ok: true, request: sanitizeSensitive(req) };
      if (req.cdpRequestId) {
        try {
          const body = await cdp.send("Network.getResponseBody", { requestId: req.cdpRequestId });
          detail.cdpResponseBody = toPreview(body, clampLimit(maxLength, DEFAULT_MAX_LENGTH, 500_000));
        } catch (error) {
          detail.cdpResponseBodyError = errorMessage(error);
        }
      }
      return detail;
    })
  );

  server.registerTool("get_api_inventory", { description: "Generate deduplicated API inventory from all observed requests.", inputSchema: { limit: z.number().int().positive().optional().default(300) } }, async ({ limit }) =>
    safeTool(async () => ({ ok: true, inventory: summarizeInventory(await getAllRequestsInternal({ limit })) }))
  );

  server.registerTool("analyze_auth_surface", { description: "Analyze authentication fields and replay hints.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, ...analyzeAuthSurfaceData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("find_idor_candidates", { description: "Find manual IDOR test candidates. Does not send requests.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, candidates: findIdorCandidatesData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("find_sensitive_data_exposure", { description: "Find sensitive fields in observed requests/responses, masked by default.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, findings: findSensitiveDataData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("find_upload_surfaces", { description: "Find upload/file related APIs and manual checks.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, surfaces: findUploadSurfacesData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("find_payment_and_order_surfaces", { description: "Find payment/order/coupon/wallet surfaces. Does not mutate or replay.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, surfaces: findPaymentOrderData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("find_debug_admin_surfaces", { description: "Find debug/test/admin/internal/dev/staging/mock indicators.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, findings: findDebugAdminData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("build_replay_plan", { description: "Build a manual replay test plan; never sends the request.", inputSchema: { requestId: z.string().min(1) } }, async ({ requestId }) =>
    safeTool(async () => {
      const req = getRequestById(await getAllRequestsInternal({ limit: 500 }), requestId);
      return req ? { ok: true, plan: buildReplayPlan(req) } : { ok: false, error: "Request not found", requestId };
    })
  );

  server.registerTool("compare_two_requests", { description: "Compare two observed requests for auth/body/response differences.", inputSchema: { requestIdA: z.string().min(1), requestIdB: z.string().min(1) } }, async ({ requestIdA, requestIdB }) =>
    safeTool(async () => {
      const requests = await getAllRequestsInternal({ limit: 500 });
      const a = getRequestById(requests, requestIdA);
      const b = getRequestById(requests, requestIdB);
      if (!a || !b) return { ok: false, error: "One or both requests not found", requestIdA, requestIdB };
      return {
        ok: true,
        urlDiff: { a: a.url, b: b.url, same: a.url === b.url },
        headerDiff: diffObjects(a.requestHeaders, b.requestHeaders),
        bodyParamDiff: diffObjects(a.requestBodyRaw ?? a.requestBodyPreview, b.requestBodyRaw ?? b.requestBodyPreview),
        authDiff: diffObjects(authIndicators(a), authIndicators(b)),
        responseDiff: diffObjects(a.responseBodyRaw ?? a.responseBodyPreview, b.responseBodyRaw ?? b.responseBodyPreview)
      };
    })
  );

  server.registerTool("passive_param_fuzz_suggestions", { description: "Generate passive fuzz suggestions only; does not send requests.", inputSchema: { requestId: z.string().min(1) } }, async ({ requestId }) =>
    safeTool(async () => {
      const req = getRequestById(await getAllRequestsInternal({ limit: 500 }), requestId);
      if (!req) return { ok: false, error: "Request not found", requestId };
      const params = [...new Set([...Object.keys(req.query), ...collectFieldKeys(req.requestBodyRaw)])];
      return {
        ok: true,
        warning: "需要授权环境中人工验证；本工具只生成 payload 建议，不自动发送。",
        requestId: req.id,
        suggestions: params.map(param => ({
          param,
          payloadTypes: ["数字边界值", "空值/null", "布尔切换", "长字符串", "特殊字符", "ID 替换", "数组/对象结构变化"],
          examplePayloads: ["0", "-1", "null", "true/false", "'\"><script>", "A".repeat(128), ID_FIELD_REGEX.test(param) ? "替换为另一个授权账号采集到的 ID" : "同类型边界值"]
        }))
      };
    })
  );

  server.registerTool("inspect_wx_config", { description: "Inspect __wxConfig, __wxAppCode__, __wxRoute, __wxAppData__ summaries.", inputSchema: { maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ maxLength }) =>
    safeTool(async () => evalJson(inspectWxConfigExpression(clampLimit(maxLength, DEFAULT_MAX_LENGTH, 200_000))))
  );

  server.registerTool("search_runtime_keywords", { description: "Search runtime, storage, scripts, and observed requests for keywords.", inputSchema: { keywords: z.array(z.string()).optional().default(DEFAULT_KEYWORDS), maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH) } }, async ({ keywords, maxLength }) =>
    safeTool(async () => {
      const limit = clampLimit(maxLength, DEFAULT_MAX_LENGTH, 200_000);
      const runtimeHits = await evalJson(searchRuntimeKeywordsExpression(keywords, limit));
      const requestHits = (await getAllRequestsInternal({ limit: 500 }))
        .flatMap(req => keywords.filter(keyword => JSON.stringify(req).toLowerCase().includes(keyword.toLowerCase())).map(keyword => ({ source: "request", keyword, requestId: req.id, path: req.path, context: truncateString(JSON.stringify(toPreview(req, 1_500)), 1_500) })))
        .slice(0, 100);
      return { ok: true, runtimeHits, requestHits };
    })
  );

  server.registerTool("trace_request_callstack", { description: "Return captured call stacks from wx/fetch/XHR hooks.", inputSchema: { requestId: z.string().optional(), limit: z.number().int().positive().optional().default(50) } }, async ({ requestId, limit }) =>
    safeTool(async () => {
      const requests = (await getAllRequestsInternal({ limit: 500 })).filter(req => req.callStack && (!requestId || req.id === requestId));
      return { ok: true, stacks: requests.slice(-clampLimit(limit, 50, 200)).map(req => ({ requestId: req.id, source: req.source, method: req.method, path: req.path, callStack: req.callStack })) };
    })
  );

  server.registerTool("inspect_vuex_store", { description: "Inspect Vuex-like store in appservice and save an original state snapshot.", inputSchema: { maxLength: z.number().int().positive().optional().default(DEFAULT_MAX_LENGTH), forceSelect: z.boolean().optional().default(false) } }, async ({ maxLength, forceSelect }) =>
    safeTool(async () => {
      const selected = await selectAppserviceContext(forceSelect);
      const result = await evalInAppservice(inspectVuexStoreExpression(clampLimit(maxLength, DEFAULT_MAX_LENGTH, 200_000)));
      return { ok: true, selected, result };
    })
  );

  server.registerTool("patch_vuex_state", { description: "Patch Vuex-like state or commit a mutation in appservice. Defaults to dryRun and requires requireConfirm=true to mutate.", inputSchema: { path: z.string().optional().default(""), value: z.unknown().optional(), commitType: z.string().optional(), payload: z.unknown().optional(), dryRun: z.boolean().optional().default(true), requireConfirm: z.boolean().optional().default(false), forceSelect: z.boolean().optional().default(false) } }, async args =>
    safeTool(async () => {
      const selected = await selectAppserviceContext(args.forceSelect);
      const result = await evalInAppservice(patchVuexStateExpression(args.path, args.value, args.dryRun, args.requireConfirm, args.commitType, args.payload));
      return {
        ok: true,
        selected,
        result,
        safety: "默认 dryRun=true；只有 dryRun=false 且 requireConfirm=true 时才会修改授权本地 Runtime 状态。"
      };
    })
  );

  server.registerTool("restore_vuex_state", { description: "Restore Vuex-like state from the snapshot saved by inspect_vuex_store. Defaults to dryRun.", inputSchema: { dryRun: z.boolean().optional().default(true), requireConfirm: z.boolean().optional().default(false), forceSelect: z.boolean().optional().default(false) } }, async ({ dryRun, requireConfirm, forceSelect }) =>
    safeTool(async () => {
      const selected = await selectAppserviceContext(forceSelect);
      const result = await evalInAppservice(restoreVuexStateExpression(dryRun, requireConfirm));
      return {
        ok: true,
        selected,
        result,
        safety: "默认 dryRun=true；只有 dryRun=false 且 requireConfirm=true 时才会恢复授权本地 Runtime 状态。"
      };
    })
  );

  server.registerTool("find_sign_related_requests", { description: "Find requests containing sign/signature/timestamp/nonce fields.", inputSchema: {} }, async () =>
    safeTool(async () => ({ ok: true, requests: findSignRequestsData(await getAllRequestsInternal({ limit: 500 })) }))
  );

  server.registerTool("export_session", { description: "Export current assessment session JSON to reports/session-*.json.", inputSchema: {} }, async () =>
    safeTool(async () => {
      const reportsDir = path.join(process.cwd(), "reports");
      fs.mkdirSync(reportsDir, { recursive: true });
      const pageInfo = cdp.isConnected() ? await evalJson(runtimeSnapshotExpression(8_000)).catch(error => ({ error: errorMessage(error) })) : { error: "CDP not connected" };
      const allRequests = await getAllRequestsInternal({ limit: 500 });
      const apiInventory = summarizeInventory(allRequests);
      const findings = buildFindings(allRequests);
      const payload = {
        exportedAt: new Date().toISOString(),
        pageInfo,
        apiInventory,
        allRequests: sanitizeSensitive(allRequests),
        console: cdp.getRecentConsole(300),
        wxRequests: sanitizeSensitive(await getHookArray("__WMPF_MCP_WX_REQUESTS__", true)),
        httpRequests: sanitizeSensitive(await getHookArray("__WMPF_MCP_HTTP_REQUESTS__")),
        findings
      };
      const filename = `session-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      const filePath = path.join(reportsDir, filename);
      fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), "utf8");
      return { ok: true, filePath, summary: { requestCount: allRequests.length, apiCount: apiInventory.length } };
    })
  );

  server.registerTool("generate_security_notes", { description: "Generate Markdown security assessment notes from observed evidence.", inputSchema: { maxLength: z.number().int().positive().optional().default(80_000) } }, async ({ maxLength }) =>
    safeTool(async () => {
      const pageInfo = cdp.isConnected() ? await evalJson(runtimeSnapshotExpression(6_000)).catch(error => ({ error: errorMessage(error) })) : { error: "CDP not connected" };
      const requests = await getAllRequestsInternal({ limit: 500 });
      const inventory = summarizeInventory(requests);
      const findings = buildFindings(requests);
      return { ok: true, markdown: truncateString(securityNotesMarkdown(pageInfo, inventory, findings), clampLimit(maxLength, 80_000, 500_000)) };
    })
  );

  server.registerTool("generate_api_table_markdown", { description: "Generate Markdown API table.", inputSchema: { maxLength: z.number().int().positive().optional().default(80_000) } }, async ({ maxLength }) =>
    safeTool(async () => {
      const markdown = apiTableMarkdown(summarizeInventory(await getAllRequestsInternal({ limit: 500 })));
      return { ok: true, markdown: truncateString(markdown, clampLimit(maxLength, 80_000, 500_000)) };
    })
  );
}

function createServer(): McpServer {
  const server = new McpServer({
    name: "wmpf-mcp-bridge",
    version: "0.1.0"
  });

  registerTools(server);
  return server;
}

function validateToken(req: Request, res: Response): boolean {
  if (req.query.token !== MCP_TOKEN) {
    res.status(401).json({
      error: "Unauthorized",
      message: "Missing or invalid MCP token."
    });
    return false;
  }

  return true;
}

const app = express();
app.use(express.json({ limit: "10mb" }));

const transports: Record<string, StreamableHTTPServerTransport> = {};

app.get("/", (_req, res) => {
  const url = `http://127.0.0.1:${MCP_PORT}/mcp?token=${MCP_TOKEN}`;
  res.type("text/plain").send(
    [
      "wmpf-mcp-bridge",
      "",
      "Streamable HTTP MCP endpoint:",
      url,
      "",
      "Codex config:",
      "[mcp_servers.wmpf]",
      "enabled = true",
      `url = "${url}"`,
      "startup_timeout_sec = 20",
      "tool_timeout_sec = 60",
      "",
      "Recommended first prompt:",
      "使用 wmpf MCP，调用 status、connect_wmpf、hook_wx_request、hook_fetch_and_xhr、dump_runtime_snapshot，然后用 get_api_inventory 和 generate_security_notes 整理接口资产与安全评估线索。"
    ].join("\n")
  );
});

app.post("/mcp", async (req, res) => {
  if (!validateToken(req, res)) {
    return;
  }

  const sessionId = req.headers["mcp-session-id"] as string | undefined;

  try {
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports[sessionId]) {
      transport = transports[sessionId];
    } else if (!sessionId && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
        onsessioninitialized: newSessionId => {
          transports[newSessionId] = transport;
        }
      });

      transport.onclose = () => {
        const closedSessionId = transport.sessionId;
        if (closedSessionId) {
          delete transports[closedSessionId];
        }
      };

      const server = createServer();
      await server.connect(transport);
    } else {
      res.status(400).json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "Bad Request: missing or invalid MCP session."
        },
        id: null
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("Error handling MCP POST:", error);
    if (!res.headersSent) {
      res.status(500).json({
        jsonrpc: "2.0",
        error: {
          code: -32603,
          message: "Internal server error"
        },
        id: null
      });
    }
  }
});

app.get("/mcp", async (req, res) => {
  if (!validateToken(req, res)) {
    return;
  }

  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;

  if (!transport) {
    res.status(400).send("Invalid or missing MCP session ID.");
    return;
  }

  await transport.handleRequest(req, res);
});

app.delete("/mcp", async (req, res) => {
  if (!validateToken(req, res)) {
    return;
  }

  const sessionId = req.headers["mcp-session-id"] as string | undefined;
  const transport = sessionId ? transports[sessionId] : undefined;

  if (!transport) {
    res.status(400).send("Invalid or missing MCP session ID.");
    return;
  }

  await transport.handleRequest(req, res);
});

app.listen(MCP_PORT, "127.0.0.1", () => {
  console.log("wmpf-mcp-bridge listening on 127.0.0.1");
  console.log(`MCP URL: http://127.0.0.1:${MCP_PORT}/mcp?token=${MCP_TOKEN}`);
  console.log(`Default CDP WebSocket: ${DEFAULT_CDP_WS_URL}`);
}).on("error", error => {
  console.error("Failed to start wmpf-mcp-bridge:", error);
  process.exit(1);
});

process.on("SIGINT", async () => {
  console.log("Shutting down wmpf-mcp-bridge...");
  cdp.close();
  for (const sessionId of Object.keys(transports)) {
    await transports[sessionId].close();
    delete transports[sessionId];
  }
  process.exit(0);
});
