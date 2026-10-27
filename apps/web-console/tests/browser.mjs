import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const origin = process.argv[2];
assert.match(origin, /^https:\/\/127\.0\.0\.1:\d+$/);
assert.ok(process.env.BROWSER_PATH, "BROWSER_PATH must name a Chromium executable");
const artifacts = resolve("../../../artifacts/console");
await mkdir(artifacts, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.BROWSER_PATH, headless: true });
const context = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1280, height: 900 } });
const page = await context.newPage();
page.setDefaultTimeout(10_000);
const errors = [];
page.on("pageerror", error => errors.push(error.message));
const control = async action => {
  const response = await context.request.post(`${origin}/__test/${action}`);
  assert.equal(response.status(), 204);
};
const heading = async text => {
  await page.getByRole("heading", { name: text, exact: true }).waitFor();
};
const noProtectedContent = async () => {
  assert.equal(await page.locator("[data-protected]").count(), 0);
  assert.doesNotMatch(await page.locator("body").innerText(), /viewer:browser|admin:browser|unknown:private/);
  assert.equal(await page.locator('input[name="_csrf"]').count(), 0);
};

try {
  for (const path of ["/console", "/console/devices", "/console/workflows", "/console/access"]) {
    const response = await context.request.get(origin + path, { maxRedirects: 0, headers: { Accept: "text/html" } });
    assert.equal(response.status(), 302);
    assert.equal(response.headers().location, `/auth/login?return_to=${encodeURIComponent(path)}`);
    assert.equal(response.headers()["cache-control"], "no-store");
    assert.doesNotMatch(await response.text(), /viewer:browser|admin:browser|_csrf/);
  }
  console.log("PASS anonymous direct navigation preserves only allowlisted destinations");

  const response = await page.goto(origin + "/console/devices");
  assert.equal(response.status(), 200);
  await heading("Devices");
  assert.equal(page.url(), origin + "/console/devices");
  assert.match(await page.locator(".account").innerText(), /viewer:browser/);
  assert.equal(await page.locator('nav a[aria-current="page"]').innerText(), "Devices");
  assert.equal(await page.getByRole("link", { name: "Console access", exact: true }).count(), 0);
  assert.equal(await page.locator("body").evaluate(el => getComputedStyle(el).fontFamily.includes("Segoe UI")), true);
  assert.equal((await context.cookies()).find(c => c.name === "__Host-device-audit-session").httpOnly, true);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  await page.screenshot({ path: resolve(artifacts, "devices-desktop.png"), fullPage: true });
  console.log("PASS real TLS OIDC/PKCE callback returns to requested protected page");

  await page.setViewportSize({ width: 320, height: 760 });
  for (const name of ["Workspace", "Devices", "Workflows"]) {
    const link = page.getByRole("navigation").getByRole("link", { name, exact: true });
    assert.ok(await link.isVisible());
    await link.click();
    await heading(name);
    const fits = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
    assert.equal(fits, true, `horizontal overflow on ${name}`);
    assert.ok(await page.getByRole("button", { name: "Sign out", exact: true }).isVisible());
  }
  await page.screenshot({ path: resolve(artifacts, "workflows-narrow.png"), fullPage: true });
  await page.goto(origin + "/console/devices");
  await page.keyboard.press("Tab");
  assert.equal(await page.evaluate(() => document.activeElement.textContent), "Skip to content");
  assert.equal(await page.evaluate(() => getComputedStyle(document.activeElement).outlineStyle), "solid");
  await page.keyboard.press("Enter");
  assert.equal(await page.evaluate(() => document.activeElement.id), "main");
  console.log("PASS 320px navigation, overflow, keyboard skip link and visible focus");

  const denied = await page.goto(origin + "/console/access");
  assert.equal(denied.status(), 403);
  await heading("Access denied");
  await noProtectedContent();
  console.log("PASS direct viewer access to administrator page is denied without bindings");

  await control("expire");
  await control("unknown");
  const expired = await page.goto(origin + "/console/workflows");
  assert.equal(expired.status(), 403);
  await heading("Sign-in denied");
  await noProtectedContent();
  console.log("PASS server-expired session requires new OIDC authentication and denies unknown account");

  await control("admin");
  await page.goto(origin + "/auth/login?return_to=/console/access");
  await heading("Console access");
  assert.match(await page.locator(".binding-list").innerText(), /viewer:browser/);
  assert.equal(await page.locator('nav a[aria-current="page"]').innerText(), "Console access");
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  console.log("PASS administrator navigation and protected role listing");

  const logoutRequest = page.waitForRequest(request => request.url().endsWith("/auth/logout"));
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  assert.equal(await (await logoutRequest).headerValue("origin"), origin);
  await heading("Signed out");
  assert.equal((await context.request.get(origin + "/auth/session")).status(), 401);
  await noProtectedContent();
  await control("unknown");
  await page.goBack();
  await heading("Sign-in denied");
  await noProtectedContent();
  console.log("PASS CSRF-protected logout revokes session; browser Back revalidates without cached content");

  await control("viewer");
  await page.goto(origin + "/auth/login");
  await heading("Workspace");
  await control("outage");
  const unavailable = await page.goto(origin + "/console/devices");
  assert.equal(unavailable.status(), 503);
  await heading("Sign-in service unavailable");
  await noProtectedContent();
  await control("restore");
  console.log("PASS auth-store outage fails closed with a recoverable public error");

  await page.clock.install();
  await page.goto(origin + "/console");
  await heading("Workspace");
  await page.clock.fastForward(16 * 60 * 1000);
  await heading("Session expired");
  await noProtectedContent();
  console.log("PASS local expiry timer clears protected content and offers sign-in");

  const noJS = await browser.newContext({ ignoreHTTPSErrors: true, javaScriptEnabled: false });
  const basicPage = await noJS.newPage();
  await basicPage.goto(origin + "/auth/login?return_to=/console/devices");
  await basicPage.getByRole("heading", { name: "Devices", exact: true }).waitFor();
  await basicPage.getByRole("navigation").getByRole("link", { name: "Workflows", exact: true }).click();
  await basicPage.getByRole("heading", { name: "Workflows", exact: true }).waitFor();
  await basicPage.getByRole("button", { name: "Sign out", exact: true }).click();
  await basicPage.getByRole("heading", { name: "Signed out", exact: true }).waitFor();
  assert.equal((await noJS.request.get(origin + "/auth/session")).status(), 401);
  await noJS.close();
  console.log("PASS login, protected navigation and form logout without JavaScript");
  assert.deepEqual(errors, [], "browser JavaScript errors");
  console.log(`Browser: ${browser.version()}; screenshots: ${artifacts}`);
} finally {
  await browser.close();
}
