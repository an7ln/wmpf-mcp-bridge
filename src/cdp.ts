import WebSocket from "ws";

export const DEFAULT_CDP_WS_URL = "ws://127.0.0.1:62000";
export const DEFAULT_CDP_TIMEOUT_MS = 10_000;
const MAX_EVENTS = 300;

type CdpParams = Record<string, unknown>;
type CdpResult = Record<string, unknown>;

export interface CdpResponse {
  id?: number;
  result?: CdpResult;
  error?: {
    code?: number;
    message?: string;
    data?: unknown;
  };
  method?: string;
  params?: CdpParams;
}

export interface PendingRequest {
  resolve: (value: CdpResult) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
  method: string;
}

export interface RuntimeEvalOptions {
  returnByValue?: boolean;
  awaitPromise?: boolean;
  timeoutMs?: number;
}

export interface CapturedCdpEvent {
  type: string;
  method: string;
  timestamp: string;
  params: CdpParams;
}

export class WmpfCdpClient {
  private ws?: WebSocket;
  private nextId = 1;
  private readonly pending = new Map<number, PendingRequest>();
  private readonly recentRequests: CapturedCdpEvent[] = [];
  private readonly recentConsole: CapturedCdpEvent[] = [];
  private currentUrl?: string;

  async connect(wsUrl = DEFAULT_CDP_WS_URL): Promise<{ connected: boolean; wsUrl: string; reused: boolean }> {
    this.assertLocalhostWsUrl(wsUrl);

    if (this.isConnected()) {
      return {
        connected: true,
        wsUrl: this.currentUrl ?? wsUrl,
        reused: true
      };
    }

    this.close();
    this.currentUrl = wsUrl;

    return new Promise((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      const timer = setTimeout(() => {
        ws.removeAllListeners();
        ws.terminate();
        reject(new Error(`Timed out connecting to ${wsUrl}`));
      }, DEFAULT_CDP_TIMEOUT_MS);

      ws.once("open", () => {
        clearTimeout(timer);
        this.ws = ws;
        this.bindSocket(ws);
        resolve({ connected: true, wsUrl, reused: false });
      });

      ws.once("error", error => {
        clearTimeout(timer);
        reject(new Error(`CDP WebSocket connection failed: ${error.message}`));
      });
    });
  }

  async send(method: string, params: CdpParams = {}, timeoutMs = DEFAULT_CDP_TIMEOUT_MS): Promise<CdpResult> {
    if (!this.isConnected() || !this.ws) {
      throw new Error("CDP WebSocket is not connected. Call connect_wmpf first.");
    }

    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP call timed out after ${timeoutMs}ms: ${method}`));
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer, method });

      this.ws!.send(payload, error => {
        if (!error) {
          return;
        }

        clearTimeout(timer);
        this.pending.delete(id);
        reject(new Error(`Failed to send CDP call ${method}: ${error.message}`));
      });
    });
  }

  async eval(expression: string, options: RuntimeEvalOptions = {}): Promise<CdpResult> {
    const {
      returnByValue = true,
      awaitPromise = true,
      timeoutMs = DEFAULT_CDP_TIMEOUT_MS
    } = options;

    return this.send(
      "Runtime.evaluate",
      {
        expression,
        returnByValue,
        awaitPromise
      },
      timeoutMs
    );
  }

  async enableRuntime(): Promise<CdpResult> {
    return this.send("Runtime.enable");
  }

  async enableNetwork(): Promise<CdpResult> {
    return this.send("Network.enable");
  }

  getRecentRequests(limit = 50): CapturedCdpEvent[] {
    return this.recentRequests.slice(-this.normalizeLimit(limit));
  }

  getRecentConsole(limit = 50): CapturedCdpEvent[] {
    return this.recentConsole.slice(-this.normalizeLimit(limit));
  }

  getRecentRequestsCount(): number {
    return this.recentRequests.length;
  }

  getRecentConsoleCount(): number {
    return this.recentConsole.length;
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  close(): void {
    for (const [id, request] of this.pending.entries()) {
      clearTimeout(request.timer);
      request.reject(new Error(`CDP client closed before response for ${request.method} (${id})`));
    }
    this.pending.clear();

    if (this.ws) {
      const ws = this.ws;
      this.ws = undefined;
      ws.removeAllListeners();
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
    }
  }

  private bindSocket(ws: WebSocket): void {
    ws.on("message", data => {
      this.handleMessage(data.toString());
    });

    ws.on("close", () => {
      if (this.ws === ws) {
        this.ws = undefined;
      }
      this.rejectAllPending("CDP WebSocket closed");
    });

    ws.on("error", error => {
      this.rejectAllPending(`CDP WebSocket error: ${error.message}`);
    });
  }

  private handleMessage(raw: string): void {
    let message: CdpResponse;

    try {
      message = JSON.parse(raw) as CdpResponse;
    } catch {
      return;
    }

    if (typeof message.id === "number") {
      this.handleResponse(message);
      return;
    }

    if (message.method && message.params) {
      this.handleEvent(message.method, message.params);
    }
  }

  private handleResponse(message: CdpResponse): void {
    if (typeof message.id !== "number") {
      return;
    }

    const pending = this.pending.get(message.id);
    if (!pending) {
      return;
    }

    clearTimeout(pending.timer);
    this.pending.delete(message.id);

    if (message.error) {
      const error = new Error(
        `CDP ${pending.method} failed: ${message.error.message ?? "Unknown error"}`
      );
      (error as Error & { code?: number; data?: unknown }).code = message.error.code;
      (error as Error & { code?: number; data?: unknown }).data = message.error.data;
      pending.reject(error);
      return;
    }

    pending.resolve(message.result ?? {});
  }

  private handleEvent(method: string, params: CdpParams): void {
    const event: CapturedCdpEvent = {
      type: this.eventType(method),
      method,
      timestamp: new Date().toISOString(),
      params
    };

    if (
      method === "Network.requestWillBeSent" ||
      method === "Network.responseReceived" ||
      method === "Network.loadingFinished"
    ) {
      this.pushLimited(this.recentRequests, event);
      return;
    }

    if (method === "Runtime.consoleAPICalled" || method === "Runtime.exceptionThrown") {
      this.pushLimited(this.recentConsole, event);
    }
  }

  private eventType(method: string): string {
    return method.slice(method.lastIndexOf(".") + 1);
  }

  private pushLimited<T>(target: T[], value: T): void {
    target.push(value);
    if (target.length > MAX_EVENTS) {
      target.splice(0, target.length - MAX_EVENTS);
    }
  }

  private rejectAllPending(message: string): void {
    for (const [id, request] of this.pending.entries()) {
      clearTimeout(request.timer);
      request.reject(new Error(`${message}; pending ${request.method} (${id}) was rejected`));
    }
    this.pending.clear();
  }

  private normalizeLimit(limit: number): number {
    if (!Number.isFinite(limit)) {
      return 50;
    }

    return Math.max(1, Math.min(MAX_EVENTS, Math.floor(limit)));
  }

  private assertLocalhostWsUrl(wsUrl: string): void {
    let parsed: URL;

    try {
      parsed = new URL(wsUrl);
    } catch {
      throw new Error(`Invalid CDP WebSocket URL: ${wsUrl}`);
    }

    if (parsed.protocol !== "ws:") {
      throw new Error("Only ws:// CDP URLs are allowed.");
    }

    if (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
      throw new Error("Only local CDP WebSocket hosts are allowed: 127.0.0.1 or localhost.");
    }
  }
}
