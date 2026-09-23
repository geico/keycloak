import { describe, expect, it } from "vitest";
import {
  BruteForceMode,
  initializePropertyPolicyOverrides,
  optionalNumber,
  propertyPolicyKey,
  toBruteForcePropertyPolicies,
} from "./bruteForcePropertyPolicies";

describe("bruteForcePropertyPolicies", () => {
  it("encodes nested form keys without treating dots as paths", () => {
    expect(propertyPolicyKey("custom.attr")).toBe("custom%2Eattr");
  });

  it("omits empty time fields so the realm inherits them", () => {
    expect(optionalNumber("")).toBeUndefined();
    expect(optionalNumber("15")).toBe(15);
  });

  it("seeds overrides when a property is added after the form is initialized", () => {
    const seeded = initializePropertyPolicyOverrides(
      { email: { enabled: true } },
      ["email", "username"],
      (property) => ({ enabled: false, property }),
    );

    expect(seeded).toEqual({
      email: { enabled: true },
      username: { enabled: false, property: "username" },
    });
  });

  it("saves every override field when a property policy is enabled", () => {
    expect(
      toBruteForcePropertyPolicies(["email", "username"], {
        email: {
          enabled: true,
          mode: BruteForceMode.TemporaryLockout,
          failureFactor: "3",
          bruteForceStrategy: "LINEAR",
          waitIncrementSeconds: "5",
          maxFailureWaitSeconds: "10",
          maxDeltaTimeSeconds: "600",
          quickLoginCheckMilliSeconds: "1000",
          minimumQuickLoginWaitSeconds: "9",
        },
        username: { enabled: false, failureFactor: "1" },
      }),
    ).toEqual({
      email: {
        permanentLockout: false,
        maxTemporaryLockouts: undefined,
        bruteForceStrategy: "LINEAR",
        maxFailureWaitSeconds: 10,
        minimumQuickLoginWaitSeconds: 9,
        waitIncrementSeconds: 5,
        quickLoginCheckMilliSeconds: 1000,
        maxDeltaTimeSeconds: 600,
        failureFactor: 3,
      },
    });
  });
});
