import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";
import { selectItem } from "../utils/form.ts";

export async function goToSecurityDefensesTab(page: Page) {
  await page.getByTestId("rs-security-defenses-tab").click();
}

export async function fillXFrameOptionsSecurityHeader(
  page: Page,
  value: string,
) {
  await page.getByTestId("browserSecurityHeaders.xFrameOptions").fill(value);
}

export async function assertXFrameOptionsSecurityHeaderValue(
  page: Page,
  expectedValue: string,
) {
  await expect(
    page.getByTestId("browserSecurityHeaders.xFrameOptions"),
  ).toHaveValue(expectedValue);
}

export async function clickSaveSecurityDefenses(page: Page) {
  await page.getByTestId("headers-form-tab-save").click();
}

export async function goToBruteForceTab(page: Page) {
  await page.getByTestId("security-defenses-brute-force-tab").click();
}

export async function selectBruteForceMode(page: Page, mode: string) {
  await selectItem(page, "#kc-brute-force-mode", mode);
}

export async function selectProtectedAuthChannels(
  page: Page,
  channels: string[],
) {
  await page.locator("#bruteForceProtectedAuthChannels").click();
  for (const channel of channels) {
    await page.getByRole("option", { name: channel, exact: true }).click();
  }
  await page.keyboard.press("Escape");
}

export async function selectAuthChannelLockScope(page: Page, scope: string) {
  await selectItem(page, "#bruteForceChannelLockScope", scope);
}

export async function selectBruteForceLockPolicy(page: Page, policy: string) {
  await selectItem(page, "#bruteForceLockPolicy", policy);
}

export async function selectProtectedUserProperties(
  page: Page,
  properties: string[],
) {
  await page.locator("#bruteForceProtectedUserProperties").click();
  for (const property of properties) {
    await page.getByRole("option", { name: property, exact: true }).click();
  }
  await page.keyboard.press("Escape");
}

export async function configureEmailPropertyPolicy(page: Page) {
  await page
    .locator("label")
    .filter({
      has: page.getByTestId("property-policy-email"),
    })
    .click();
  await selectItem(
    page,
    '[id="bruteForcePropertyPolicyOverrides.email.mode"]',
    "Lockout temporarily",
  );
  await page
    .locator(
      '[id="bruteForcePropertyPolicyOverrides.email.failureFactor"] input',
    )
    .fill("3");
  await selectItem(
    page,
    '[id="bruteForcePropertyPolicyOverrides.email.bruteForceStrategy"]',
    "Linear",
  );
  await page
    .getByTestId("bruteForcePropertyPolicyOverrides.email.waitIncrementSeconds")
    .fill("5");
  await page
    .getByTestId(
      "bruteForcePropertyPolicyOverrides.email.maxFailureWaitSeconds",
    )
    .fill("10");
  await page
    .getByTestId("bruteForcePropertyPolicyOverrides.email.maxDeltaTimeSeconds")
    .fill("600");
  await page
    .locator(
      '[id="bruteForcePropertyPolicyOverrides.email.quickLoginCheckMilliSeconds"] input',
    )
    .fill("1000");
  await page
    .getByTestId(
      "bruteForcePropertyPolicyOverrides.email.minimumQuickLoginWaitSeconds",
    )
    .fill("9");
}

export async function fillMaxChannelFailures(page: Page, value: string) {
  await page.locator("#bruteForceChannelFailureFactor input").fill(value);
}

export async function fillWaitIncrementSeconds(page: Page, value: string) {
  await page.getByTestId("waitIncrementSeconds").fill(value);
}

export async function fillMaxFailureWaitSeconds(page: Page, value: string) {
  await page.getByTestId("maxFailureWaitSeconds").fill(value);
}

export async function fillMaxDeltaTimeSeconds(page: Page, value: string) {
  await page.getByTestId("maxDeltaTimeSeconds").fill(value);
}

export async function fillMinimumQuickLoginWaitSeconds(
  page: Page,
  value: string,
) {
  await page.getByTestId("minimumQuickLoginWaitSeconds").fill(value);
}

export async function clickSaveBruteForce(page: Page) {
  await page.getByTestId("brute-force-tab-save").click();
}
