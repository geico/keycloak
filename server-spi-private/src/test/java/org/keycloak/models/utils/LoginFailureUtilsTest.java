/*
 * Copyright 2026 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.models.utils;

import java.lang.reflect.Proxy;
import java.util.Map;

import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.BruteForcePolicyRepresentation;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceLockPolicy;

import org.junit.Assert;
import org.junit.Test;

public class LoginFailureUtilsTest {

    @Test
    public void usesTheLongestPropertyResetWindowForProviderRetention() {
        BruteForcePolicyRepresentation email = new BruteForcePolicyRepresentation();
        email.setMaxDeltaTimeSeconds(600);
        BruteForcePolicyRepresentation phone = new BruteForcePolicyRepresentation();
        phone.setMaxDeltaTimeSeconds(120);

        Assert.assertEquals(600, LoginFailureUtils.getMaxDeltaTimeSeconds(
                realm(false, 0, 300, Map.of("email", email, "phoneNumber", phone))));
    }

    @Test
    public void permanentOnlyPropertyMakesProviderRetentionNonExpiring() {
        BruteForcePolicyRepresentation email = new BruteForcePolicyRepresentation();
        email.setPermanentLockout(true);
        email.setMaxTemporaryLockouts(0);

        Assert.assertTrue(LoginFailureUtils.hasNonExpiringFailures(
                realm(false, 0, 300, Map.of("email", email))));
    }

    @Test
    public void inactivePropertyPoliciesDoNotChangeUserOnlyRetention() {
        BruteForcePolicyRepresentation email = new BruteForcePolicyRepresentation();
        email.setPermanentLockout(true);
        email.setMaxTemporaryLockouts(0);
        email.setMaxDeltaTimeSeconds(600);

        RealmModel realm = realm(false, 0, 300, Map.of("email", email), BruteForceLockPolicy.USER);
        Assert.assertFalse(LoginFailureUtils.hasNonExpiringFailures(realm));
        Assert.assertEquals(300, LoginFailureUtils.getMaxDeltaTimeSeconds(realm));
    }

    @Test
    public void expirationCutoffUsesTheLongestResetWindow() {
        BruteForcePolicyRepresentation email = new BruteForcePolicyRepresentation();
        email.setMaxDeltaTimeSeconds(600);
        RealmModel realm = realm(false, 0, 300, Map.of("email", email));

        Assert.assertEquals(1_000L, LoginFailureUtils.computeExpirationCutOffTimestampMillis(realm, 601_000L));
    }

    @Test
    public void permanentOnlyRealmsNeverExpireFailures() {
        RealmModel realm = realm(true, 0, 300, Map.of());
        Assert.assertEquals(-1L, LoginFailureUtils.computeExpirationCutOffTimestampMillis(realm, 1_000L));
    }

    private static RealmModel realm(boolean permanentLockout, int maxTemporaryLockouts, int maxDeltaTimeSeconds,
            Map<String, BruteForcePolicyRepresentation> policies) {
        return realm(permanentLockout, maxTemporaryLockouts, maxDeltaTimeSeconds, policies,
                BruteForceLockPolicy.PROPERTIES);
    }

    private static RealmModel realm(boolean permanentLockout, int maxTemporaryLockouts, int maxDeltaTimeSeconds,
            Map<String, BruteForcePolicyRepresentation> policies, BruteForceLockPolicy lockPolicy) {
        return (RealmModel) Proxy.newProxyInstance(LoginFailureUtilsTest.class.getClassLoader(),
                new Class<?>[] { RealmModel.class }, (proxy, method, args) -> switch (method.getName()) {
                    case "isPermanentLockout" -> permanentLockout;
                    case "getMaxTemporaryLockouts" -> maxTemporaryLockouts;
                    case "getMaxDeltaTimeSeconds" -> maxDeltaTimeSeconds;
                    case "getBruteForcePropertyPolicies" -> policies;
                    case "getBruteForceLockPolicy" -> lockPolicy;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
