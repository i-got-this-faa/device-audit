import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const fixtures = JSON.parse(await readFile(new URL("../fixtures/devices.json", import.meta.url), "utf8"));
assert.equal(fixtures.fixture, true);
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
  assert.doesNotMatch(await page.locator("body").innerText(), /viewer:browser|admin:browser|unknown:private|Operations laptop|Stores workstation/);
  assert.equal(await page.locator('input[name="_csrf"]').count(), 0);
};

try {
  for (const path of ["/console", "/console/devices", "/console/devices/fixture-laptop", "/console/workflows", "/console/access"]) {
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

  const fits = async () => assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `horizontal overflow at ${page.url()}`);
  const fixtureNotice = async () => {
    assert.ok(await page.locator(".fixture-context").getByText("Fixture data", { exact: true }).isVisible());
    assert.match(await page.getByRole("note").innerText(), /synthetic.*not production telemetry/s);
    assert.ok(await page.getByRole("note").getByText(fixtures.fixed_time, { exact: true }).isVisible());
  };
  // Both the renderer and browser use the same named fixture catalogue.
  for (const width of [1280, 640, 320]) {
    await page.setViewportSize({ width, height: 900 });
    for (const scenario of fixtures.scenarios) {
      const path = `/console/devices?fixture=${scenario.name}`;
      const list = await page.goto(origin + path);
      assert.equal(list.status(), scenario.state === "error" ? 503 : 200);
      await fixtureNotice();
      await fits();
      assert.equal(await page.locator(".device-list > li").count(), scenario.device_ids.length);
      for (const id of scenario.device_ids) {
        const device = fixtures.devices.find(device => device.id === id);
        const row = page.locator(".device-list > li").filter({ hasText: id });
        assert.equal(await row.locator(".fixture-badge").innerText(), "Fixture");
        assert.equal(await row.locator(".device-status").getAttribute("data-state"), device.state);
        await row.getByRole("link", { name: device.name, exact: true }).click();
        await heading(device.name);
        await fixtureNotice();
        await fits();
        assert.equal(await page.locator('nav[aria-label="Main navigation"] a[aria-current="page"]').innerText(), "Devices");
        const sensors = page.locator(".sensor-list");
        if (id === "fixture-laptop") {
          assert.equal(await sensors.locator("div").filter({ hasText: "CPU utilization" }).locator(".sensor-value").innerText(), "0");
          for (const reason of ["Sensor unavailable", "Sensor does not apply", "Collection permission denied", "Collection failed"]) {
            assert.ok(await sensors.getByText(reason, { exact: false }).isVisible());
          }
          assert.match(await page.locator(".component-list").innerText(), /Model unknown: not reported/);
          await sensors.getByText("Network latency", { exact: true }).scrollIntoViewIfNeeded();
          const badge = await page.locator(".fixture-context .fixture-badge").boundingBox();
          assert.ok(badge && badge.y >= 0 && badge.y + badge.height <= 900, "fixture badge must remain in view while reading measurements");
          await page.evaluate(() => window.scrollTo(0, 0));
          await page.screenshot({ path: resolve(artifacts, `device-detail-${width}.png`), fullPage: true });
        } else if (id === "fixture-unknown") {
          assert.equal(await sensors.locator(".sensor-value").allTextContents().then(values => values.every(value => value === "Unknown")), true);
          assert.match(await page.locator(".inventory-empty").innerText(), /Inventory unknown/);
        } else {
          assert.match(await page.locator(".inventory-empty").innerText(), /No components reported/);
          assert.match(await sensors.innerText(), /Not reported in this sample/);
        }
        if (device.state === "offline") assert.match(await page.locator(".state-warning").innerText(), /historical.*current device condition is unknown/);
        await page.getByRole("link", { name: "Back to device list", exact: false }).click();
        assert.equal(page.url(), origin + path);
      }
      if (["loading", "error", "empty"].includes(scenario.state)) {
        assert.equal(await page.locator(".sensor-list, .device-list").count(), 0);
        await page.screenshot({ path: resolve(artifacts, `devices-${scenario.name}-${width}.png`), fullPage: true });
        const detail = await page.goto(`${origin}/console/devices/fixture-laptop?fixture=${scenario.name}`);
        assert.equal(detail.status(), scenario.state === "error" ? 503 : 200);
        await fixtureNotice();
        await fits();
        assert.equal(await page.locator(".sensor-list").count(), 0);
        await page.getByRole("link", { name: scenario.state === "empty" ? "Open populated fixture" : "Load ready fixture", exact: true }).click();
        await fixtureNotice();
        assert.ok(await page.locator(scenario.state === "empty" ? ".device-list" : ".sensor-list").isVisible());
      }
    }
  }
  await page.goto(origin + "/console/devices/fixture-laptop");
  for (const [label, deviceName] of [["Offline sample", "Stores workstation"], ["Unknown sample", "Unreported device"], ["Empty component inventory", "Replay device"]]) {
    await page.getByRole("navigation", { name: "Fixture scenarios", exact: true }).getByRole("link", { name: label, exact: true }).click();
    await heading(deviceName);
    await fixtureNotice();
    await fits();
  }
  console.log("PASS detail scenario controls select compatible device samples");
  // A 640 CSS-pixel viewport covers reflow equivalent to 200% zoom on a 1280px layout.
  console.log("PASS named fixture list/detail states at 1280, 640 and 320px; provenance, missing reasons, stale evidence, zero values and recovery");
  for (const path of ["/console/devices/no-such-device", "/console/devices?fixture=missing", "/console/devices?fixture=live&fixture=error"]) {
    assert.equal((await page.goto(origin + path)).status(), 404);
    await fixtureNotice();
    assert.equal(await page.locator(".sensor-list, .device-list").count(), 0);
  }
  await page.goto(origin + "/console/devices?fixture=offline");
  await page.getByRole("link", { name: "Stores workstation", exact: true }).click();
  await page.goBack();
  await heading("Devices");
  await fixtureNotice();
  assert.equal(page.url(), origin + "/console/devices?fixture=offline");
  console.log("PASS invalid fixture/device selections and browser Back preserve explicit fixture state");

  await page.setViewportSize({ width: 320, height: 760 });
  for (const name of ["Workspace", "Devices", "Workflows"]) {
    const link = page.getByRole("navigation", { name: "Main navigation", exact: true }).getByRole("link", { name, exact: true });
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
  const expired = await page.goto(origin + "/console/devices/fixture-laptop");
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
  const unavailable = await page.goto(origin + "/console/devices/fixture-laptop");
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
  await basicPage.getByRole("link", { name: "Operations laptop", exact: true }).click();
  await basicPage.getByRole("heading", { name: "Operations laptop", exact: true }).waitFor();
  assert.match(await basicPage.locator(".sensor-list").innerText(), /Sensor unavailable/);
  await basicPage.getByRole("link", { name: "Read error", exact: true }).click();
  assert.ok(await basicPage.getByRole("alert").isVisible());
  await basicPage.getByRole("link", { name: "Load ready fixture", exact: true }).click();
  assert.ok(await basicPage.locator(".sensor-list").isVisible());
  await basicPage.getByRole("navigation", { name: "Main navigation", exact: true }).getByRole("link", { name: "Workflows", exact: true }).click();
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
