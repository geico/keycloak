import type { BruteForcePolicyRepresentation } from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";

export const propertyPolicyKey = (property: string) =>
  encodeURIComponent(property).replaceAll(".", "%2E");

export const optionalNumber = (value: unknown) => {
  if (value === "" || value === null || value === undefined) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
};

export enum BruteForceMode {
  Disabled = "Disabled",
  PermanentLockout = "PermanentLockout",
  TemporaryLockout = "TemporaryLockout",
  PermanentAfterTemporaryLockout = "PermanentAfterTemporaryLockout",
}

export const modeFor = (
  permanentLockout?: boolean,
  maxTemporaryLockouts?: number,
) =>
  !permanentLockout
    ? BruteForceMode.TemporaryLockout
    : maxTemporaryLockouts === 0
      ? BruteForceMode.PermanentLockout
      : BruteForceMode.PermanentAfterTemporaryLockout;

type PropertyPolicyFormValue = {
  enabled?: boolean;
  mode?: BruteForceMode;
  failureFactor?: unknown;
  bruteForceStrategy?: BruteForcePolicyRepresentation["bruteForceStrategy"];
  maxFailureWaitSeconds?: unknown;
  minimumQuickLoginWaitSeconds?: unknown;
  waitIncrementSeconds?: unknown;
  quickLoginCheckMilliSeconds?: unknown;
  maxDeltaTimeSeconds?: unknown;
  maxTemporaryLockouts?: unknown;
};

export const initializePropertyPolicyOverrides = <T>(
  current: Record<string, T> | undefined,
  properties: string[],
  formValue: (property: string) => T,
) => {
  const next = { ...(current ?? {}) };
  let changed = false;
  for (const property of properties) {
    const key = propertyPolicyKey(property);
    if (next[key] === undefined) {
      next[key] = formValue(property);
      changed = true;
    }
  }
  return changed ? next : current;
};

export const toBruteForcePropertyPolicies = (
  protectedProperties: string[],
  overrides: Record<string, PropertyPolicyFormValue> | undefined,
): Record<string, BruteForcePolicyRepresentation> =>
  Object.fromEntries(
    protectedProperties.flatMap((property) => {
      const policy = overrides?.[propertyPolicyKey(property)];
      if (!policy?.enabled) {
        return [];
      }
      const permanentLockout = policy.mode !== BruteForceMode.TemporaryLockout;
      const maxTemporaryLockouts =
        policy.mode === BruteForceMode.PermanentLockout
          ? 0
          : policy.maxTemporaryLockouts;
      return [
        [
          property,
          {
            permanentLockout,
            maxTemporaryLockouts: optionalNumber(maxTemporaryLockouts),
            bruteForceStrategy: policy.bruteForceStrategy,
            maxFailureWaitSeconds: optionalNumber(policy.maxFailureWaitSeconds),
            minimumQuickLoginWaitSeconds: optionalNumber(
              policy.minimumQuickLoginWaitSeconds,
            ),
            waitIncrementSeconds: optionalNumber(policy.waitIncrementSeconds),
            quickLoginCheckMilliSeconds: optionalNumber(
              policy.quickLoginCheckMilliSeconds,
            ),
            maxDeltaTimeSeconds: optionalNumber(policy.maxDeltaTimeSeconds),
            failureFactor: optionalNumber(policy.failureFactor),
          },
        ],
      ];
    }),
  );
