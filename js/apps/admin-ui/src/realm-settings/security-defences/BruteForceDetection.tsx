import type RealmRepresentation from "@keycloak/keycloak-admin-client/lib/defs/realmRepresentation";
import type { UserProfileConfig } from "@keycloak/keycloak-admin-client/lib/defs/userProfileMetadata";
import {
  HelpItem,
  KeycloakSelect,
  NumberControl,
  SelectVariant,
  SelectControl,
  useFetch,
} from "@keycloak/keycloak-ui-shared";
import {
  ActionGroup,
  Button,
  FormGroup,
  SelectOption,
  Switch,
} from "@patternfly/react-core";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Controller, FormProvider, useForm } from "react-hook-form";
import { useTranslation } from "react-i18next";
import { useAdminClient } from "../../admin-client";
import { FormAccess } from "../../components/form/FormAccess";
import { convertToFormValues } from "../../util";
import {
  BruteForceMode,
  initializePropertyPolicyOverrides,
  modeFor,
  propertyPolicyKey,
  toBruteForcePropertyPolicies,
} from "./bruteForcePropertyPolicies";
import { Time } from "./Time";

const BUILT_IN_USER_PROPERTIES = [
  "id",
  "username",
  "email",
  "firstName",
  "lastName",
];

// Categories the server tracks for brute force. Custom authenticators report their own category,
// which is preserved in the options once configured.
const BUILT_IN_AUTH_CHANNELS = ["password", "otp", "recovery-authn-codes"];

type BruteForceDetectionProps = {
  realm: RealmRepresentation;
  save: (realm: RealmRepresentation) => void;
};

export const BruteForceDetection = ({
  realm,
  save,
}: BruteForceDetectionProps) => {
  const { t } = useTranslation();
  const { adminClient } = useAdminClient();
  const form = useForm();
  const {
    setValue,
    handleSubmit,
    formState: { isDirty },
  } = form;

  const [isBruteForceModeOpen, setIsBruteForceModeOpen] = useState(false);
  const [isBruteForceModeUpdated, setIsBruteForceModeUpdated] = useState(false);
  const [userProfile, setUserProfile] = useState<UserProfileConfig>();

  useFetch(() => adminClient.users.getProfile(), setUserProfile, []);

  const lockPropertyOptions = useMemo(() => {
    const names = new Set(BUILT_IN_USER_PROPERTIES);
    userProfile?.attributes?.forEach((attribute) => {
      if (attribute.name) {
        names.add(attribute.name);
      }
    });
    realm.bruteForceProtectedUserProperties?.forEach((property) =>
      names.add(property),
    );
    return [...names];
  }, [userProfile, realm.bruteForceProtectedUserProperties]);

  const lockChannelOptions = useMemo(() => {
    const names = new Set(BUILT_IN_AUTH_CHANNELS);
    realm.bruteForceProtectedAuthChannels?.forEach((channel) =>
      names.add(channel),
    );
    return [...names];
  }, [realm.bruteForceProtectedAuthChannels]);

  const bruteForceModes = [
    BruteForceMode.Disabled,
    BruteForceMode.PermanentLockout,
    BruteForceMode.TemporaryLockout,
    BruteForceMode.PermanentAfterTemporaryLockout,
  ];

  const bruteForceStrategyTypes = ["MULTIPLE", "LINEAR"];
  const bruteForceLockPolicies = ["USER", "PROPERTIES", "ANY"] as const;
  const bruteForceChannelLockScopes = ["ACCOUNT", "CHANNEL"] as const;

  const propertyPolicyFormValue = useCallback(
    (property: string) => {
      const policy = realm.bruteForcePropertyPolicies?.[property];
      return {
        enabled: policy !== undefined,
        mode: modeFor(
          policy?.permanentLockout ?? realm.permanentLockout,
          policy?.maxTemporaryLockouts ?? realm.maxTemporaryLockouts,
        ),
        failureFactor:
          policy?.failureFactor ??
          realm.bruteForcePropertyFailureFactor ??
          realm.failureFactor ??
          0,
        bruteForceStrategy:
          policy?.bruteForceStrategy ?? realm.bruteForceStrategy,
        maxFailureWaitSeconds:
          policy?.maxFailureWaitSeconds ?? realm.maxFailureWaitSeconds,
        minimumQuickLoginWaitSeconds:
          policy?.minimumQuickLoginWaitSeconds ??
          realm.minimumQuickLoginWaitSeconds,
        waitIncrementSeconds:
          policy?.waitIncrementSeconds ?? realm.waitIncrementSeconds,
        quickLoginCheckMilliSeconds:
          policy?.quickLoginCheckMilliSeconds ??
          realm.quickLoginCheckMilliSeconds,
        maxDeltaTimeSeconds:
          policy?.maxDeltaTimeSeconds ?? realm.maxDeltaTimeSeconds,
        maxTemporaryLockouts:
          policy?.maxTemporaryLockouts ?? realm.maxTemporaryLockouts,
      };
    },
    [realm],
  );

  const setupForm = () => {
    convertToFormValues(realm, setValue);
    setValue("bruteForceLockPolicy", realm.bruteForceLockPolicy ?? "USER");
    setValue(
      "bruteForceChannelLockScope",
      realm.bruteForceChannelLockScope ?? "ACCOUNT",
    );
    setValue(
      "bruteForcePropertyPolicyOverrides",
      Object.fromEntries(
        (realm.bruteForceProtectedUserProperties ?? []).map((property) => [
          propertyPolicyKey(property),
          propertyPolicyFormValue(property),
        ]),
      ),
    );
    setIsBruteForceModeUpdated(false);
  };
  useEffect(setupForm, [realm, setValue, propertyPolicyFormValue]);

  const lockPolicy = form.watch("bruteForceLockPolicy") ?? "USER";
  const protectedProperties: string[] =
    form.watch("bruteForceProtectedUserProperties") ?? [];
  const protectedChannels: string[] =
    form.watch("bruteForceProtectedAuthChannels") ?? [];

  useEffect(() => {
    const current = form.getValues("bruteForcePropertyPolicyOverrides");
    const next = initializePropertyPolicyOverrides(
      current,
      protectedProperties,
      propertyPolicyFormValue,
    );
    if (next !== current) {
      setValue("bruteForcePropertyPolicyOverrides", next);
    }
  }, [form, protectedProperties, propertyPolicyFormValue, setValue]);

  const bruteForceMode = (() => {
    if (!form.getValues("bruteForceProtected")) {
      return BruteForceMode.Disabled;
    }
    if (!form.getValues("permanentLockout")) {
      return BruteForceMode.TemporaryLockout;
    }
    return form.getValues("maxTemporaryLockouts") == 0
      ? BruteForceMode.PermanentLockout
      : BruteForceMode.PermanentAfterTemporaryLockout;
  })();

  const saveRealm = (values: RealmRepresentation & Record<string, any>) => {
    const bruteForcePropertyPolicies = toBruteForcePropertyPolicies(
      protectedProperties,
      values.bruteForcePropertyPolicyOverrides,
    );
    const realmValues = { ...values };
    delete realmValues.bruteForcePropertyPolicyOverrides;
    save({ ...realmValues, bruteForcePropertyPolicies });
  };

  return (
    <FormProvider {...form}>
      <FormAccess
        role="manage-realm"
        isHorizontal
        onSubmit={handleSubmit(saveRealm)}
      >
        <FormGroup
          label={t("bruteForceMode")}
          fieldId="kc-brute-force-mode"
          labelIcon={
            <HelpItem
              helpText={t("bruteForceModeHelpText")}
              fieldLabelId="bruteForceMode"
            />
          }
        >
          <KeycloakSelect
            toggleId="kc-brute-force-mode"
            onToggle={() => setIsBruteForceModeOpen(!isBruteForceModeOpen)}
            onSelect={(value) => {
              switch (value as BruteForceMode) {
                case BruteForceMode.Disabled:
                  form.setValue("bruteForceProtected", false);
                  form.setValue("permanentLockout", false);
                  form.setValue("maxTemporaryLockouts", 0);
                  break;
                case BruteForceMode.TemporaryLockout:
                  form.setValue("bruteForceProtected", true);
                  form.setValue("permanentLockout", false);
                  form.setValue("maxTemporaryLockouts", 0);
                  break;
                case BruteForceMode.PermanentLockout:
                  form.setValue("bruteForceProtected", true);
                  form.setValue("permanentLockout", true);
                  form.setValue("maxTemporaryLockouts", 0);
                  break;
                case BruteForceMode.PermanentAfterTemporaryLockout:
                  form.setValue("bruteForceProtected", true);
                  form.setValue("permanentLockout", true);
                  form.setValue("maxTemporaryLockouts", 1);
                  break;
              }
              setIsBruteForceModeUpdated(true);
              setIsBruteForceModeOpen(false);
            }}
            selections={bruteForceMode}
            variant={SelectVariant.single}
            isOpen={isBruteForceModeOpen}
            data-testid="select-brute-force-mode"
            aria-label={t("selectUnmanagedAttributePolicy")}
          >
            {bruteForceModes.map((mode) => (
              <SelectOption key={mode} value={mode}>
                {t(`bruteForceMode.${mode}`)}
              </SelectOption>
            ))}
          </KeycloakSelect>
        </FormGroup>
        {bruteForceMode !== BruteForceMode.Disabled && (
          <>
            <NumberControl
              name="failureFactor"
              label={t("failureFactor")}
              labelIcon={t("failureFactorHelp")}
              controller={{
                defaultValue: 0,
                rules: { required: t("required"), min: 0 },
              }}
            />
            {lockPolicy !== "USER" && (
              <NumberControl
                name="bruteForcePropertyFailureFactor"
                label={t("bruteForcePropertyFailureFactor")}
                labelIcon={t("bruteForcePropertyFailureFactorHelp")}
                controller={{
                  defaultValue:
                    realm.bruteForcePropertyFailureFactor ??
                    realm.failureFactor ??
                    0,
                  rules: { required: t("required"), min: 0 },
                }}
              />
            )}
            <NumberControl
              name="maxSecondaryAuthFailures"
              label={t("maxSecondaryAuthFailures")}
              labelIcon={t("maxSecondaryAuthFailuresHelp")}
              controller={{
                defaultValue: 100,
                rules: { required: t("required"), min: 0 },
              }}
            />
            <SelectControl
              name="bruteForceLockPolicy"
              label={t("bruteForceLockPolicy")}
              labelIcon={t("bruteForceLockPolicyHelp")}
              controller={{ defaultValue: "USER" }}
              options={bruteForceLockPolicies.map((key) => ({
                key,
                value: t(`bruteForceLockPolicy.${key}`),
              }))}
            />
            {lockPolicy !== "USER" && (
              <SelectControl
                name="bruteForceProtectedUserProperties"
                label={t("bruteForceProtectedUserProperties")}
                labelIcon={t("bruteForceProtectedUserPropertiesHelp")}
                controller={{
                  defaultValue: [],
                  rules: { required: t("required") },
                }}
                variant={SelectVariant.typeaheadMulti}
                placeholderText={t(
                  "bruteForceProtectedUserPropertiesPlaceholder",
                )}
                chipGroupProps={{
                  numChips: 3,
                  expandedText: t("hide"),
                  collapsedText: t("showRemaining"),
                }}
                options={lockPropertyOptions}
              />
            )}
            {lockPolicy !== "USER" && protectedProperties.length > 0 && (
              <FormGroup
                label={t("bruteForcePropertyPolicies")}
                fieldId="bruteForcePropertyPolicies"
                labelIcon={
                  <HelpItem
                    helpText={t("bruteForcePropertyPoliciesHelp")}
                    fieldLabelId="bruteForcePropertyPolicies"
                  />
                }
              >
                {protectedProperties
                  .filter((property) => property !== "id")
                  .map((property) => {
                    const prefix = `bruteForcePropertyPolicyOverrides.${propertyPolicyKey(property)}`;
                    const enabled = form.watch(`${prefix}.enabled`) ?? false;
                    const mode =
                      form.watch(`${prefix}.mode`) ??
                      modeFor(
                        form.getValues("permanentLockout"),
                        form.getValues("maxTemporaryLockouts"),
                      );
                    return (
                      <div key={property} className="pf-v5-u-mb-lg">
                        <Controller
                          name={`${prefix}.enabled`}
                          control={form.control}
                          defaultValue={false}
                          render={({ field }) => (
                            <Switch
                              id={`property-policy-${propertyPolicyKey(property)}`}
                              data-testid={`property-policy-${property}`}
                              label={property}
                              labelOff={property}
                              isChecked={field.value}
                              onChange={(_event, checked) =>
                                field.onChange(checked)
                              }
                            />
                          )}
                        />
                        {enabled && (
                          <>
                            <SelectControl
                              name={`${prefix}.mode`}
                              label={t("bruteForceMode")}
                              controller={{
                                defaultValue: modeFor(
                                  form.getValues("permanentLockout"),
                                  form.getValues("maxTemporaryLockouts"),
                                ),
                              }}
                              options={bruteForceModes
                                .filter(
                                  (candidate) =>
                                    candidate !== BruteForceMode.Disabled,
                                )
                                .map((candidate) => ({
                                  key: candidate,
                                  value: t(`bruteForceMode.${candidate}`),
                                }))}
                            />
                            <NumberControl
                              name={`${prefix}.failureFactor`}
                              label={t("bruteForcePropertyFailureFactor")}
                              labelIcon={t("bruteForcePropertyFailureFactorHelp")}
                              controller={{
                                defaultValue:
                                  form.getValues(
                                    "bruteForcePropertyFailureFactor",
                                  ) ??
                                  form.getValues("failureFactor") ??
                                  0,
                                rules: { required: t("required"), min: 0 },
                              }}
                            />
                            {mode ===
                              BruteForceMode.PermanentAfterTemporaryLockout && (
                              <NumberControl
                                name={`${prefix}.maxTemporaryLockouts`}
                                label={t("maxTemporaryLockouts")}
                                labelIcon={t("maxTemporaryLockoutsHelp")}
                                controller={{
                                  defaultValue:
                                    form.getValues("maxTemporaryLockouts") ?? 1,
                                  rules: { required: t("required"), min: 0 },
                                }}
                              />
                            )}
                            {mode !== BruteForceMode.PermanentLockout && (
                              <>
                                <SelectControl
                                  name={`${prefix}.bruteForceStrategy`}
                                  label={t("bruteForceStrategy")}
                                  labelIcon={t("bruteForceStrategyHelp", {
                                    failureFactor:
                                      form.getValues(`${prefix}.failureFactor`) ??
                                      form.getValues("failureFactor"),
                                  })}
                                  controller={{
                                    defaultValue:
                                      form.getValues("bruteForceStrategy"),
                                  }}
                                  options={bruteForceStrategyTypes.map(
                                    (key) => ({
                                      key,
                                      value: t(`bruteForceStrategy.${key}`),
                                    }),
                                  )}
                                />
                                <Time
                                  name={`${prefix}.waitIncrementSeconds`}
                                  labelName="waitIncrementSeconds"
                                  defaultValue={form.getValues(
                                    "waitIncrementSeconds",
                                  )}
                                  min={0}
                                />
                                <Time
                                  name={`${prefix}.maxFailureWaitSeconds`}
                                  labelName="maxFailureWaitSeconds"
                                  defaultValue={form.getValues(
                                    "maxFailureWaitSeconds",
                                  )}
                                  min={0}
                                />
                                <Time
                                  name={`${prefix}.maxDeltaTimeSeconds`}
                                  labelName="maxDeltaTimeSeconds"
                                  defaultValue={form.getValues(
                                    "maxDeltaTimeSeconds",
                                  )}
                                  min={0}
                                />
                              </>
                            )}
                            <NumberControl
                              name={`${prefix}.quickLoginCheckMilliSeconds`}
                              label={t("quickLoginCheckMilliSeconds")}
                              labelIcon={t("quickLoginCheckMilliSecondsHelp")}
                              controller={{
                                defaultValue:
                                  form.getValues(
                                    "quickLoginCheckMilliSeconds",
                                  ) ?? 0,
                                rules: { required: t("required"), min: 0 },
                              }}
                            />
                            <Time
                              name={`${prefix}.minimumQuickLoginWaitSeconds`}
                              labelName="minimumQuickLoginWaitSeconds"
                              defaultValue={form.getValues(
                                "minimumQuickLoginWaitSeconds",
                              )}
                              min={0}
                            />
                          </>
                        )}
                      </div>
                    );
                  })}
              </FormGroup>
            )}
            <SelectControl
              name="bruteForceProtectedAuthChannels"
              label={t("bruteForceProtectedAuthChannels")}
              labelIcon={t("bruteForceProtectedAuthChannelsHelp")}
              controller={{ defaultValue: [] }}
              variant={SelectVariant.typeaheadMulti}
              placeholderText={t("bruteForceProtectedAuthChannelsPlaceholder")}
              chipGroupProps={{
                numChips: 3,
                expandedText: t("hide"),
                collapsedText: t("showRemaining"),
              }}
              options={lockChannelOptions}
            />
            {protectedChannels.length > 0 && (
              <>
                <SelectControl
                  name="bruteForceChannelLockScope"
                  label={t("bruteForceChannelLockScope")}
                  labelIcon={t("bruteForceChannelLockScopeHelp")}
                  controller={{ defaultValue: "ACCOUNT" }}
                  options={bruteForceChannelLockScopes.map((key) => ({
                    key,
                    value: t(`bruteForceChannelLockScope.${key}`),
                  }))}
                />
                <NumberControl
                  name="bruteForceChannelFailureFactor"
                  label={t("bruteForceChannelFailureFactor")}
                  labelIcon={t("bruteForceChannelFailureFactorHelp")}
                  controller={{
                    defaultValue:
                      realm.bruteForceChannelFailureFactor ??
                      realm.failureFactor ??
                      0,
                    rules: { required: t("required"), min: 0 },
                  }}
                />
              </>
            )}
            {bruteForceMode ===
              BruteForceMode.PermanentAfterTemporaryLockout && (
              <NumberControl
                name="maxTemporaryLockouts"
                label={t("maxTemporaryLockouts")}
                labelIcon={t("maxTemporaryLockoutsHelp")}
                controller={{
                  defaultValue: 0,
                  rules: { min: 0 },
                }}
              />
            )}
            {(bruteForceMode === BruteForceMode.TemporaryLockout ||
              bruteForceMode ===
                BruteForceMode.PermanentAfterTemporaryLockout) && (
              <>
                <SelectControl
                  name="bruteForceStrategy"
                  label={t("bruteForceStrategy")}
                  labelIcon={t("bruteForceStrategyHelp", {
                    failureFactor: form.getValues("failureFactor"),
                  })}
                  controller={{ defaultValue: "" }}
                  options={bruteForceStrategyTypes.map((key) => ({
                    key,
                    value: t(`bruteForceStrategy.${key}`),
                  }))}
                />
                <Time name="waitIncrementSeconds" min={0} />
                <Time name="maxFailureWaitSeconds" min={0} />
                <Time name="maxDeltaTimeSeconds" min={0} />
              </>
            )}
            <NumberControl
              name="quickLoginCheckMilliSeconds"
              label={t("quickLoginCheckMilliSeconds")}
              labelIcon={t("quickLoginCheckMilliSecondsHelp")}
              controller={{
                defaultValue: 0,
                rules: { min: 0 },
              }}
            />
            <Time name="minimumQuickLoginWaitSeconds" min={0} />
          </>
        )}

        <ActionGroup>
          <Button
            variant="primary"
            type="submit"
            data-testid="brute-force-tab-save"
            isDisabled={!isDirty && !isBruteForceModeUpdated}
          >
            {t("save")}
          </Button>
          <Button variant="link" onClick={setupForm}>
            {t("revert")}
          </Button>
        </ActionGroup>
      </FormAccess>
    </FormProvider>
  );
};
