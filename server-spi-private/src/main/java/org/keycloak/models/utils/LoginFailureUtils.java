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

import java.util.concurrent.TimeUnit;

import org.keycloak.models.RealmModel;
import org.keycloak.representations.idm.BruteForcePolicyRepresentation;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceLockPolicy;

/**
 * <p>Shared methods to calculate login failure idle times.</p>
 */
public class LoginFailureUtils {

    /**
     * Compute the expiration time cut-off in milliseconds for expiring login failure entries.
     *
     * @param realm current realm
     * @param currentTimeMillis current timestamp in milliseconds since last epoch
     * @return Timestamp in milliseconds, or -1L if the realm will never expire.
     */
    public static long computeExpirationCutOffTimestampMillis(RealmModel realm, long currentTimeMillis) {
        if (hasNonExpiringFailures(realm)) {
            // If mode is permanent lockout only, the "failure reset time" cannot be configured and login failures should never expire.
            return -1L;
        }
        // expired if last-failure + max-delta-time < current time
        return currentTimeMillis - TimeUnit.SECONDS.toMillis(getMaxDeltaTimeSeconds(realm));
    }

    /**
     * Login-failure providers expire entries per realm rather than per counter key. Retain all
     * entries for the longest effective property reset window so a longer property override is not
     * evicted early.
     */
    public static int getMaxDeltaTimeSeconds(RealmModel realm) {
        if (realm.getBruteForceLockPolicy() == BruteForceLockPolicy.USER) {
            return realm.getMaxDeltaTimeSeconds();
        }
        return realm.getBruteForcePropertyPolicies().values().stream()
                .map(BruteForcePolicyRepresentation::getMaxDeltaTimeSeconds)
                .filter(value -> value != null)
                .reduce(realm.getMaxDeltaTimeSeconds(), Math::max);
    }

    /**
     * A permanent-only property counter must survive provider cleanup even when the realm's account
     * policy is temporary. Providers cannot safely distinguish hashed property keys, so retention
     * is conservatively realm-wide.
     */
    public static boolean hasNonExpiringFailures(RealmModel realm) {
        if (realm.isPermanentLockout() && realm.getMaxTemporaryLockouts() == 0) {
            return true;
        }
        if (realm.getBruteForceLockPolicy() == BruteForceLockPolicy.USER) {
            return false;
        }
        return realm.getBruteForcePropertyPolicies().values().stream().anyMatch(policy -> {
            boolean permanent = policy.isPermanentLockout() == null
                    ? realm.isPermanentLockout()
                    : policy.isPermanentLockout();
            int temporaryLockouts = policy.getMaxTemporaryLockouts() == null
                    ? realm.getMaxTemporaryLockouts()
                    : policy.getMaxTemporaryLockouts();
            return permanent && temporaryLockouts == 0;
        });
    }

}
