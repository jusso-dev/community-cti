import { createServer, type IncomingMessage, type OutgoingHttpHeaders, type Server, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  ORG_TYPES,
  renderAlertsPage,
  renderCheckEmailPage,
  renderDomainsPage,
  renderFindingDetail,
  renderFindingsPage,
  renderLoginPage,
  renderMessagePage,
  renderNotificationSettings,
  renderOnboardingPage,
  type Advisory,
  type OnboardingValues,
  type PortalDomain,
  type PortalFinding,
  type RansomwareSummary,
} from "./index.js";

export interface PortalOptions {
  apiUrl: string;
  fetchImpl?: typeof fetch;
}

interface Me {
  user: { id: string; email: string };
  tenantId: string | null;
  role: string | null;
  org: { id: string; name: string; orgType: string } | null;
  consented?: boolean;
}

interface ApiResponse<T> {
  status: number;
  ok: boolean;
  data: T;
  headers: Headers;
}

interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  form: URLSearchParams;
  api: <T>(method: string, path: string, body?: unknown) => Promise<ApiResponse<T>>;
}

type Handler = (ctx: Ctx, params: string[]) => Promise<void>;

const BODY_LIMIT = 16 * 1024;
const API_TIMEOUT_MS = 10_000;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
const SCRIPT_PATH = fileURLToPath(new URL("../client/app.js", import.meta.url));
const CLEAR_COOKIE = "cti_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax";
const MODES = ["immediate", "digest", "off"];
const NOTICES: Record<string, string> = {
  added: "We added your domain. Now show us you control it.",
  verified: "Your domain is verified. We are watching it now.",
  "email-sent": "We sent the email. Open the link in it to finish.",
  saved: "Your alert settings are saved.",
  stopped: "We have stopped watching your domains. To start again, give consent below.",
};
const SECURITY_HEADERS: OutgoingHttpHeaders = {
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
};

class HttpError extends Error {
  constructor(readonly status: number, readonly title: string, message: string, readonly link?: { href: string; text: string }) {
    super(message);
  }
}

class Redirect extends Error {
  constructor(readonly location: string) {
    super(location);
  }
}

class ApiUnavailable extends Error {}

const notFound = () => new HttpError(404, "Page not found", "We could not find that page. Check the address, or go back to your findings.");

function sendHtml(res: ServerResponse, status: number, html: string, headers: OutgoingHttpHeaders = {}): void {
  res.writeHead(status, { ...SECURITY_HEADERS, "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(html);
}

function redirect(res: ServerResponse, location: string, headers: OutgoingHttpHeaders = {}): void {
  res.writeHead(303, { ...SECURITY_HEADERS, location, ...headers });
  res.end();
}

function apiError(response: ApiResponse<unknown>): string {
  const message = (response.data as { error?: unknown } | null)?.error;
  return typeof message === "string" && message ? message : "That did not work. Please try again.";
}

function unwrap<T>(response: ApiResponse<T>): T {
  if (response.status === 404) throw notFound();
  if (!response.ok) throw new HttpError(400, "That did not work", apiError(response));
  return response.data;
}

function crossOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (!origin) return false;
  try {
    return new URL(origin).host !== req.headers.host;
  } catch {
    return true;
  }
}

function readForm(req: IncomingMessage): Promise<URLSearchParams> {
  return new Promise((resolve, reject) => {
    const tooLarge = () => new HttpError(413, "That was too much", "What you sent was too large. Please send less and try again.");
    if (Number(req.headers["content-length"] ?? 0) > BODY_LIMIT) return reject(tooLarge());
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > BODY_LIMIT) {
        req.removeAllListeners("data");
        req.resume();
        reject(tooLarge());
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(new URLSearchParams(Buffer.concat(chunks).toString("utf8"))));
    req.on("error", reject);
  });
}

async function callApi<T>(fetchImpl: typeof fetch, base: string, cookie: string | undefined, method: string, path: string, body?: unknown): Promise<ApiResponse<T>> {
  let response: Response;
  try {
    response = await fetchImpl(`${base}${path}`, {
      method,
      headers: { accept: "application/json", "content-type": "application/json", ...(cookie ? { cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(API_TIMEOUT_MS),
    });
  } catch {
    throw new ApiUnavailable();
  }
  if (response.status >= 500) throw new ApiUnavailable();
  if (response.status === 401) throw new Redirect("/login");
  const text = await response.text();
  let data: unknown = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = null;
  }
  return { status: response.status, ok: response.ok, data: data as T, headers: response.headers };
}

function sessionCookies(headers: Headers): string[] {
  return headers.getSetCookie()
    .filter((value) => value.startsWith("cti_session="))
    .map((value) => (/;\s*path=/i.test(value) ? value : `${value}; Path=/`));
}

async function signedIn(ctx: Ctx, needs: "user" | "tenant" | "consent" = "consent"): Promise<Me> {
  const me = unwrap(await ctx.api<Me>("GET", "/me"));
  if (needs !== "user" && !me.tenantId) throw new Redirect("/onboarding");
  if (needs === "consent" && me.consented === false) throw new Redirect("/onboarding");
  return me;
}

function notice(ctx: Ctx): string | undefined {
  return NOTICES[ctx.url.searchParams.get("notice") ?? ""];
}

function field(form: URLSearchParams, name: string): string {
  return (form.get(name) ?? "").trim();
}

const enc = encodeURIComponent;

async function healthz(ctx: Ctx): Promise<void> {
  ctx.res.writeHead(200, { ...SECURITY_HEADERS, "content-type": "application/json" });
  ctx.res.end(JSON.stringify({ ok: true }));
}

async function script(ctx: Ctx): Promise<void> {
  const body = await readFile(SCRIPT_PATH);
  ctx.res.writeHead(200, { ...SECURITY_HEADERS, "content-type": "text/javascript; charset=utf-8", "cache-control": "public, max-age=3600" });
  ctx.res.end(body);
}

async function loginPage(ctx: Ctx): Promise<void> {
  sendHtml(ctx.res, 200, renderLoginPage());
}

async function login(ctx: Ctx): Promise<void> {
  const email = field(ctx.form, "email");
  if (!/^[^@\s]+@[^@\s]+$/.test(email)) {
    return sendHtml(ctx.res, 400, renderLoginPage({ email, error: "Enter your email address, like name@example.org.au." }));
  }
  const response = await ctx.api("POST", "/auth/magic-link", { email });
  if (!response.ok) return sendHtml(ctx.res, 400, renderLoginPage({ email, error: apiError(response) }));
  sendHtml(ctx.res, 200, renderCheckEmailPage());
}

async function callback(ctx: Ctx): Promise<void> {
  const token = ctx.url.searchParams.get("token") ?? "";
  const retry = { href: "/login", text: "Get a new sign-in link" };
  if (!token) throw new HttpError(400, "That link did not work", "The sign-in link is missing part of its address.", retry);
  const response = await ctx.api("GET", `/auth/callback?token=${enc(token)}`);
  if (!response.ok) throw new HttpError(400, "That link did not work", "This sign-in link has expired or was already used. Each link only works once.", retry);
  redirect(ctx.res, "/", { "set-cookie": sessionCookies(response.headers) });
}

async function logout(ctx: Ctx): Promise<void> {
  try {
    await ctx.api("POST", "/auth/logout", {});
  } catch {
    // Clear the browser cookie even when the API cannot be reached.
  }
  redirect(ctx.res, "/login", { "set-cookie": CLEAR_COOKIE });
}

async function home(ctx: Ctx): Promise<void> {
  await signedIn(ctx);
  const findings = unwrap(await ctx.api<PortalFinding[]>("GET", "/findings"));
  sendHtml(ctx.res, 200, renderFindingsPage(findings));
}

async function alertsPage(ctx: Ctx): Promise<void> {
  await signedIn(ctx, "tenant");
  const [advisories, ransomware] = await Promise.all([
    ctx.api<Advisory[]>("GET", "/advisories"),
    ctx.api<RansomwareSummary>("GET", "/ransomware/au"),
  ]);
  sendHtml(ctx.res, 200, renderAlertsPage(unwrap(advisories), unwrap(ransomware)));
}

async function onboardingPage(ctx: Ctx): Promise<void> {
  const me = await signedIn(ctx, "user");
  sendHtml(ctx.res, 200, renderOnboardingPage({ needsOrg: !me.tenantId, notice: notice(ctx) }));
}

function onboardingError(values: OnboardingValues, consent: boolean, needsOrg: boolean): string | undefined {
  if (needsOrg && !values.name) return "Enter your organisation name.";
  if (needsOrg && !ORG_TYPES.some(([value]) => value === values.orgType)) return "Choose what kind of organisation it is.";
  if (!values.grantorName) return "Enter the name of the person giving consent.";
  if (!values.grantorRole) return "Enter the role of the person giving consent.";
  if (!consent) return "Tick the box to give consent.";
  return undefined;
}

async function onboard(ctx: Ctx): Promise<void> {
  const me = await signedIn(ctx, "user");
  const values: OnboardingValues = {
    name: field(ctx.form, "name"),
    orgType: field(ctx.form, "orgType"),
    grantorName: field(ctx.form, "grantorName"),
    grantorRole: field(ctx.form, "grantorRole"),
  };
  let orgId = me.tenantId;
  const error = onboardingError(values, ctx.form.get("consent") === "yes", !orgId);
  if (error) return sendHtml(ctx.res, 400, renderOnboardingPage({ needsOrg: !orgId, values, error }));
  if (!orgId) {
    const created = await ctx.api<{ id: string }>("POST", "/orgs", { name: values.name, orgType: values.orgType });
    if (!created.ok) return sendHtml(ctx.res, 400, renderOnboardingPage({ needsOrg: true, values, error: apiError(created) }));
    orgId = created.data.id;
  }
  const consent = await ctx.api("POST", `/orgs/${enc(orgId)}/consents`, { scope: "domain_monitoring", grantorName: values.grantorName, grantorRole: values.grantorRole });
  if (!consent.ok) return sendHtml(ctx.res, 400, renderOnboardingPage({ needsOrg: false, values, error: apiError(consent) }));
  redirect(ctx.res, "/domains");
}

async function findingPage(ctx: Ctx, [id]: string[]): Promise<void> {
  const finding = unwrap(await ctx.api<PortalFinding>("GET", `/findings/${enc(id!)}`));
  sendHtml(ctx.res, 200, renderFindingDetail(finding));
}

async function findingAction(ctx: Ctx, [id, action]: string[]): Promise<void> {
  const comment = field(ctx.form, "comment");
  const body = action === "dismiss"
    ? { reason: field(ctx.form, "reason"), ...(comment ? { comment } : {}) }
    : action === "challenge" ? { comment } : {};
  const response = await ctx.api("POST", `/findings/${enc(id!)}/${action}`, body);
  if (response.ok) return redirect(ctx.res, `/findings/${enc(id!)}`);
  if (response.status === 404) throw notFound();
  const finding = unwrap(await ctx.api<PortalFinding>("GET", `/findings/${enc(id!)}`));
  sendHtml(ctx.res, 400, renderFindingDetail(finding, { error: apiError(response) }));
}

async function domainsPage(ctx: Ctx): Promise<void> {
  await signedIn(ctx);
  const domains = unwrap(await ctx.api<PortalDomain[]>("GET", "/domains"));
  sendHtml(ctx.res, 200, renderDomainsPage(domains, { notice: notice(ctx) }));
}

async function domainsError(ctx: Ctx, response: ApiResponse<unknown>): Promise<void> {
  if (response.status === 404) throw notFound();
  const domains = unwrap(await ctx.api<PortalDomain[]>("GET", "/domains"));
  sendHtml(ctx.res, 400, renderDomainsPage(domains, { error: apiError(response) }));
}

async function addDomain(ctx: Ctx): Promise<void> {
  const response = await ctx.api("POST", "/domains", { domain: field(ctx.form, "domain") });
  if (response.ok) return redirect(ctx.res, "/domains?notice=added");
  await domainsError(ctx, response);
}

async function domainAction(ctx: Ctx, [id, action]: string[]): Promise<void> {
  const response = action === "check"
    ? await ctx.api("POST", `/domains/${enc(id!)}/check`, {})
    : await ctx.api("POST", `/domains/${enc(id!)}/email`, { email: field(ctx.form, "email") });
  if (response.ok) return redirect(ctx.res, `/domains?notice=${action === "check" ? "verified" : "email-sent"}`);
  await domainsError(ctx, response);
}

async function verifyEmail(ctx: Ctx): Promise<void> {
  const token = ctx.url.searchParams.get("token") ?? "";
  const link = { href: "/domains", text: "Go to your domains" };
  const response = token ? await ctx.api("GET", `/domains/verify-email?token=${enc(token)}`) : undefined;
  if (!response?.ok) throw new HttpError(404, "That link did not work", "This link has expired or was already used. You can send a new one from your domains page.", link);
  sendHtml(ctx.res, 200, renderMessagePage("Domain verified", "Thank you. Your domain is verified and we are watching it now.", link));
}

function canStop(me: Me): boolean {
  return me.role === "owner" && me.consented !== false;
}

async function settingsPage(ctx: Ctx): Promise<void> {
  const me = await signedIn(ctx, "tenant");
  const prefs = unwrap(await ctx.api<{ mode: string }>("GET", "/notifications/preferences"));
  sendHtml(ctx.res, 200, renderNotificationSettings(prefs.mode, { notice: notice(ctx), canStop: canStop(me) }));
}

async function saveSettings(ctx: Ctx): Promise<void> {
  const me = await signedIn(ctx, "tenant");
  const mode = field(ctx.form, "mode");
  if (!MODES.includes(mode)) return sendHtml(ctx.res, 400, renderNotificationSettings("", { error: "Choose how we should email you.", canStop: canStop(me) }));
  const response = await ctx.api("PUT", "/notifications/preferences", { mode });
  if (!response.ok) return sendHtml(ctx.res, 400, renderNotificationSettings(mode, { error: apiError(response), canStop: canStop(me) }));
  redirect(ctx.res, "/settings/notifications?notice=saved");
}

async function stopMonitoring(ctx: Ctx): Promise<void> {
  const me = await signedIn(ctx, "tenant");
  if (me.role !== "owner") {
    throw new HttpError(403, "Only an owner can do this", "Ask an owner of your organisation to stop watching your domains.", { href: "/settings/notifications", text: "Back to alert settings" });
  }
  const confirmed = ctx.form.get("confirm") === "yes";
  const response = confirmed ? await ctx.api("POST", `/orgs/${enc(me.tenantId!)}/consents/revoke`, {}) : undefined;
  if (response?.ok) return redirect(ctx.res, "/onboarding?notice=stopped");
  const prefs = unwrap(await ctx.api<{ mode: string }>("GET", "/notifications/preferences"));
  const error = response ? apiError(response) : "Tick the box to confirm you want us to stop.";
  sendHtml(ctx.res, 400, renderNotificationSettings(prefs.mode, { error, canStop: true }));
}

const ROUTES: Array<[string, RegExp, Handler]> = [
  ["GET", /^\/healthz$/, healthz],
  ["GET", /^\/app\.js$/, script],
  ["GET", /^\/login$/, loginPage],
  ["POST", /^\/login$/, login],
  ["GET", /^\/auth\/callback$/, callback],
  ["POST", /^\/logout$/, logout],
  ["GET", /^\/$/, home],
  ["GET", /^\/alerts$/, alertsPage],
  ["GET", /^\/onboarding$/, onboardingPage],
  ["POST", /^\/onboarding$/, onboard],
  ["GET", /^\/findings\/([^/]+)$/, findingPage],
  ["POST", /^\/findings\/([^/]+)\/(dismiss|challenge|reopen)$/, findingAction],
  ["GET", /^\/domains$/, domainsPage],
  ["POST", /^\/domains$/, addDomain],
  ["GET", /^\/domains\/verify-email$/, verifyEmail],
  ["POST", /^\/domains\/([^/]+)\/(check|email)$/, domainAction],
  ["GET", /^\/settings\/notifications$/, settingsPage],
  ["POST", /^\/settings\/notifications$/, saveSettings],
  ["POST", /^\/settings\/stop-monitoring$/, stopMonitoring],
];

function route(method: string, pathname: string): { handler: Handler; params: string[] } | undefined {
  for (const [routeMethod, pattern, handler] of ROUTES) {
    const match = routeMethod === method ? pattern.exec(pathname) : null;
    if (!match) continue;
    const params = match.slice(1);
    if (params[0] !== undefined && !ID.test(params[0])) return undefined;
    return { handler, params };
  }
  return undefined;
}

function fail(req: IncomingMessage, res: ServerResponse, pathname: string, error: unknown): void {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  if (error instanceof Redirect) return redirect(res, error.location);
  if (error instanceof HttpError) {
    return sendHtml(res, error.status, renderMessagePage(error.title, error.message, error.link), error.status === 413 ? { connection: "close" } : {});
  }
  if (error instanceof ApiUnavailable) {
    return sendHtml(res, 502, renderMessagePage("We could not load this page", "Our service is not answering right now. Please try again in a few minutes."));
  }
  console.error(`portal error on ${req.method} ${pathname}: ${error instanceof Error ? error.message : "unknown"}`);
  sendHtml(res, 500, renderMessagePage("Something went wrong", "Something went wrong on our side. Please try again."));
}

export function createPortal(options: PortalOptions): Server {
  const fetchImpl = options.fetchImpl ?? fetch;
  const base = options.apiUrl.replace(/\/+$/, "");
  return createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://portal.invalid");
    try {
      const method = req.method ?? "GET";
      const found = route(method, url.pathname);
      if (!found) throw notFound();
      if (method === "POST" && crossOrigin(req)) throw new HttpError(403, "That form came from another website", "For your safety we did not accept it. Please go back and try again from this site.");
      const form = method === "POST" ? await readForm(req) : new URLSearchParams();
      const cookie = req.headers.cookie;
      const api = <T>(apiMethod: string, path: string, body?: unknown) => callApi<T>(fetchImpl, base, cookie, apiMethod, path, body);
      await found.handler({ req, res, url, form, api }, found.params);
    } catch (error) {
      fail(req, res, url.pathname, error);
    }
  });
}
