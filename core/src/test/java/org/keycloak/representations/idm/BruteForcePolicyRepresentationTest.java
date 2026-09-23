package org.keycloak.representations.idm;

import java.util.Collections;
import java.util.Map;

import org.keycloak.util.JsonSerialization;

import org.junit.Assert;
import org.junit.Test;

public class BruteForcePolicyRepresentationTest {

    @Test
    public void roundTripsEveryOptionalPolicyField() throws Exception {
        BruteForcePolicyRepresentation policy = new BruteForcePolicyRepresentation();
        policy.setPermanentLockout(false);
        policy.setMaxTemporaryLockouts(2);
        policy.setBruteForceStrategy(RealmRepresentation.BruteForceStrategy.LINEAR);
        policy.setMaxFailureWaitSeconds(120);
        policy.setMinimumQuickLoginWaitSeconds(9);
        policy.setWaitIncrementSeconds(15);
        policy.setQuickLoginCheckMilliSeconds(1000L);
        policy.setMaxDeltaTimeSeconds(600);
        policy.setFailureFactor(3);

        RealmRepresentation realm = new RealmRepresentation();
        realm.setBruteForceProtectedUserProperties(Collections.singletonList("email"));
        realm.setBruteForcePropertyPolicies(Collections.singletonMap("email", policy));

        RealmRepresentation parsed = JsonSerialization.readValue(JsonSerialization.writeValueAsString(realm),
                RealmRepresentation.class);
        BruteForcePolicyRepresentation stored = parsed.getBruteForcePropertyPolicies().get("email");

        Assert.assertEquals(Collections.singletonList("email"), parsed.getBruteForceProtectedUserProperties());
        Assert.assertFalse(stored.isPermanentLockout());
        Assert.assertEquals(Integer.valueOf(2), stored.getMaxTemporaryLockouts());
        Assert.assertEquals(RealmRepresentation.BruteForceStrategy.LINEAR, stored.getBruteForceStrategy());
        Assert.assertEquals(Integer.valueOf(120), stored.getMaxFailureWaitSeconds());
        Assert.assertEquals(Integer.valueOf(9), stored.getMinimumQuickLoginWaitSeconds());
        Assert.assertEquals(Integer.valueOf(15), stored.getWaitIncrementSeconds());
        Assert.assertEquals(Long.valueOf(1000L), stored.getQuickLoginCheckMilliSeconds());
        Assert.assertEquals(Integer.valueOf(600), stored.getMaxDeltaTimeSeconds());
        Assert.assertEquals(Integer.valueOf(3), stored.getFailureFactor());
    }
}
