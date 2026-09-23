import { expect, test } from "@playwright/test";
import { v4 as uuid } from "uuid";
import adminClient from "../utils/AdminClient.ts";
import { login } from "../utils/login.ts";
import { assertNotificationMessage } from "../utils/masthead.ts";
import { goToRealm, goToRealmSettings } from "../utils/sidebar.ts";
import {
  clickSaveBruteForce,
  fillXFrameOptionsSecurityHeader,
  assertXFrameOptionsSecurityHeaderValue,
  clickSaveSecurityDefenses,
  selectBruteForceMode,
  selectBruteForceLockPolicy,
  selectProtectedUserProperties,
  configureEmailPropertyPolicy,
  selectProtectedAuthChannels,
  selectAuthChannelLockScope,
  fillMaxChannelFailures,
  fillMaxDeltaTimeSeconds,
  fillMaxFailureWaitSeconds,
  fillMinimumQuickLoginWaitSeconds,
  fillWaitIncrementSeconds,
  goToSecurityDefensesTab,
  goToBruteForceTab,
} from "./security-defenses.ts";

test.describe.serial("Security defenses", () => {
  const realmName = `security-defenses-realm-settings-${uuid()}`;

  test.beforeAll(() => adminClient.createRealm(realmName));
  test.afterAll(() => adminClient.deleteRealm(realmName));

  test.beforeEach(async ({ page }) => {
    await login(page);
    await goToRealm(page, realmName);
    await goToRealmSettings(page);
    await goToSecurityDefensesTab(page);
  });

  test("Realm header settings", async ({ page }) => {
    await fillXFrameOptionsSecurityHeader(page, "DENY");
    await clickSaveSecurityDefenses(page);
    await assertNotificationMessage(page, "Realm successfully updated");
    await assertXFrameOptionsSecurityHeaderValue(page, "DENY");
    expect(
      (await adminClient.getRealm(realmName))?.browserSecurityHeaders
        ?.xFrameOptions,
    ).toBe("DENY");
  });

  test("Brute force detection", async ({ page }) => {
    await goToBruteForceTab(page);
    await selectBruteForceMode(page, "Lockout temporarily");
    await fillWaitIncrementSeconds(page, "1");
    await fillMaxFailureWaitSeconds(page, "1");
    await fillMaxDeltaTimeSeconds(page, "1");
    await fillMinimumQuickLoginWaitSeconds(page, "1");
    await selectBruteForceLockPolicy(page, "Shared properties only");
    await selectProtectedUserProperties(page, ["username", "email"]);
    await configureEmailPropertyPolicy(page);
    await selectProtectedAuthChannels(page, ["password", "otp"]);
    await selectAuthChannelLockScope(page, "Lock only that channel");
    await fillMaxChannelFailures(page, "2");
    await clickSaveBruteForce(page);
    await assertNotificationMessage(page, "Realm successfully updated");

    const realm = await adminClient.getRealm(realmName);
    expect(realm?.bruteForceProtectedAuthChannels).toEqual(["password", "otp"]);
    expect(realm?.bruteForceChannelLockScope).toBe("CHANNEL");
    expect(realm?.bruteForceChannelFailureFactor).toBe(2);
    expect(realm?.bruteForcePropertyPolicies?.email).toMatchObject({
      permanentLockout: false,
      failureFactor: 3,
      bruteForceStrategy: "LINEAR",
      waitIncrementSeconds: 300,
      maxFailureWaitSeconds: 600,
      maxDeltaTimeSeconds: 2160000,
      quickLoginCheckMilliSeconds: 1000,
      minimumQuickLoginWaitSeconds: 540,
    });
  });

  test("Realm header settings followed by Brute force detection", async ({
    page,
  }) => {
    await fillXFrameOptionsSecurityHeader(page, "ALLOW-FROM foo");
    await clickSaveSecurityDefenses(page);
    await assertNotificationMessage(page, "Realm successfully updated");

    await goToBruteForceTab(page);
    await selectBruteForceMode(page, "Lockout temporarily");
    await fillWaitIncrementSeconds(page, "2");
    await clickSaveBruteForce(page);
    await assertNotificationMessage(page, "Realm successfully updated");

    await goToSecurityDefensesTab(page);
    await assertXFrameOptionsSecurityHeaderValue(page, "ALLOW-FROM foo");
    expect(
      (await adminClient.getRealm(realmName))?.browserSecurityHeaders
        ?.xFrameOptions,
    ).toBe("ALLOW-FROM foo");
  });
});
