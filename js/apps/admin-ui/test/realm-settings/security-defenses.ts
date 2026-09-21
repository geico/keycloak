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
