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
package org.keycloak.services.managers;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserLoginFailureProvider;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceChannelLockScope;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceLockPolicy;

import org.junit.Assert;
import org.junit.Test;

public class BruteForceAuthChannelTest {

    private static final String PASSWORD = "password";
    private static final String OTP = "otp";

    @Test
    public void noChannelsAreProtectedByDefault() {
        RealmModel realm = realm();

        Assert.assertEquals(List.of(), BruteForceAuthChannel.getProtectedChannels(realm));
        Assert.assertFalse(BruteForceAuthChannel.isProtected(realm, PASSWORD));
        Assert.assertNull(BruteForceAuthChannel.resolveChannel(realm, Set.of(PASSWORD)));
    }

    @Test
    public void resolvesOnlyProtectedChannels() {
        RealmModel realm = realm(PASSWORD);

        Assert.assertEquals(PASSWORD, BruteForceAuthChannel.resolveChannel(realm, Set.of(PASSWORD)));
        Assert.assertNull(BruteForceAuthChannel.resolveChannel(realm, Set.of(OTP)));
        Assert.assertNull(BruteForceAuthChannel.resolveChannel(realm, Set.of()));
        Assert.assertNull(BruteForceAuthChannel.resolveChannel(realm, null));
    }

    @Test
    public void channelIdsAreCaseInsensitive() {
        RealmModel realm = realm("Password");

        Assert.assertEquals(List.of(PASSWORD), BruteForceAuthChannel.getProtectedChannels(realm));
        Assert.assertTrue(BruteForceAuthChannel.isProtected(realm, "PASSWORD"));
        Assert.assertEquals(PASSWORD, BruteForceAuthChannel.resolveChannel(realm, Set.of("PASSWORD")));
    }

    @Test
    public void customAuthenticatorCategoriesBecomeTheirOwnChannel() {
        RealmModel realm = realm("sms-otp", OTP);
        UserModel user = user("user-id", "username", "user@example.com");

        Assert.assertEquals("sms-otp", BruteForceAuthChannel.resolveChannel(realm, Set.of("sms-otp")));
        Assert.assertNotEquals(
                BruteForceAuthChannel.getFailureKeys(realm, user, "sms-otp"),
                BruteForceAuthChannel.getFailureKeys(realm, user, OTP));
    }

    @Test
    public void channelsKeepSeparateCounters() {
        RealmModel realm = realm(PASSWORD, OTP);
        UserModel user = user("user-id", "username", "user@example.com");

        Assert.assertNotEquals(
                BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD),
                BruteForceAuthChannel.getFailureKeys(realm, user, OTP));
    }

    @Test
    public void channelCountersAreSeparateFromTheAccountCounter() {
        RealmModel realm = realm(PASSWORD);
        UserModel user = user("user-id", "username", "user@example.com");

        Assert.assertEquals(List.of("user-id"), BruteForceUserProperty.getFailureKeys(realm, user));
        Assert.assertFalse(BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD).contains("user-id"));
    }

    @Test
    public void channelCountersWrapEveryCounterOfTheLockPolicy() {
        RealmModel realm = realm(BruteForceLockPolicy.ANY, BruteForceChannelLockScope.ACCOUNT, 30, null,
                List.of("email"), List.of(OTP));
        UserModel user = user("user-id", "username", "user@example.com");

        Assert.assertEquals(2, BruteForceAuthChannel.getFailureKeys(realm, user, OTP).size());
        Assert.assertEquals(2, BruteForceAuthChannel.getAllFailureKeys(realm, user).size());
    }

    @Test
    public void attemptIncrementsOnlyTheSubmittedIdentifierForThatChannel() {
        RealmModel realm = realm(BruteForceLockPolicy.PROPERTIES, BruteForceChannelLockScope.CHANNEL, 30, null,
                List.of("username", "email"), List.of(PASSWORD));
        UserModel user = user("user-id", "username", "user@example.com");

        Assert.assertEquals(
                BruteForceAuthChannel.getFailureKeysForAttempt(realm, user, PASSWORD, "username"),
                List.of(BruteForceAuthChannel.channelKey(PASSWORD,
                        BruteForceUserProperty.propertyKey("username", "username"))));
        Assert.assertEquals(List.of(),
                BruteForceAuthChannel.getFailureKeysForAttempt(realm, user, PASSWORD, "nobody@example.com"));
    }

    @Test
    public void usersSharingAPropertyValueShareThatChannelCounter() {
        RealmModel realm = realm(BruteForceLockPolicy.PROPERTIES, BruteForceChannelLockScope.CHANNEL, 30, null,
                List.of("email"), List.of(OTP));
        UserModel firstUser = user("first-user", "first", "shared@example.com");
        UserModel secondUser = user("second-user", "second", "shared@example.com");

        Assert.assertEquals(
                BruteForceAuthChannel.getFailureKeys(realm, firstUser, OTP),
                BruteForceAuthChannel.getFailureKeys(realm, secondUser, OTP));
    }

    @Test
    public void accountLockScopeIsTheDefault() {
        Assert.assertTrue(BruteForceAuthChannel.locksAccount(realm(PASSWORD)));
        Assert.assertFalse(BruteForceAuthChannel.locksAccount(
                realm(BruteForceLockPolicy.USER, BruteForceChannelLockScope.CHANNEL, 30, null, List.of(),
                        List.of(PASSWORD))));
    }

    @Test
    public void channelCountersUseTheChannelFailureFactor() {
        RealmModel realm = realm(BruteForceLockPolicy.USER, BruteForceChannelLockScope.CHANNEL, 30, 3, List.of(),
                List.of(PASSWORD));
        UserModel user = user("user-id", "username", "user@example.com");
        String channelKey = BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD).get(0);

        Assert.assertEquals(30, BruteForceUserProperty.getFailureFactor(realm, "user-id"));
        Assert.assertEquals(3, BruteForceUserProperty.getFailureFactor(realm, channelKey));
    }

    @Test
    public void channelFailureFactorFallsBackToFailureFactor() {
        RealmModel realm = realm(PASSWORD);
        UserModel user = user("user-id", "username", "user@example.com");
        String channelKey = BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD).get(0);

        Assert.assertEquals(30, BruteForceUserProperty.getFailureFactor(realm, channelKey));
    }

    @Test
    public void reportsAChannelBlockedByItsOwnCounter() {
        RealmModel realm = realm(BruteForceLockPolicy.USER, BruteForceChannelLockScope.CHANNEL, 30, 2, List.of(),
                List.of(PASSWORD, OTP));
        UserModel user = user("user-id", "username", "user@example.com");
        Map<String, UserLoginFailureModel> failures = new HashMap<>();
        failures.put(BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD).get(0), loginFailure(2, 0));
        KeycloakSession session = session(failures);

        Assert.assertTrue(BruteForceAuthChannel.isPermanentlyLocked(session, realm, user, PASSWORD));
        Assert.assertFalse(BruteForceAuthChannel.isPermanentlyLocked(session, realm, user, OTP));
    }

    @Test
    public void reportsATemporarilyBlockedChannel() {
        RealmModel realm = realm(BruteForceLockPolicy.USER, BruteForceChannelLockScope.CHANNEL, 30, 2, List.of(),
                List.of(PASSWORD, OTP));
        UserModel user = user("user-id", "username", "user@example.com");
        Map<String, UserLoginFailureModel> failures = new HashMap<>();
        failures.put(BruteForceAuthChannel.getFailureKeys(realm, user, OTP).get(0),
                loginFailure(1, Time.currentTime() + 60));
        KeycloakSession session = session(failures);

        Assert.assertTrue(BruteForceAuthChannel.isTemporarilyLocked(session, realm, user, OTP));
        Assert.assertFalse(BruteForceAuthChannel.isTemporarilyLocked(session, realm, user, PASSWORD));
    }

    @Test
    public void unprotectedChannelsAreNeverLocked() {
        RealmModel realm = realm(PASSWORD);
        UserModel user = user("user-id", "username", "user@example.com");
        KeycloakSession session = session(new HashMap<>());

        Assert.assertFalse(BruteForceAuthChannel.isTemporarilyLocked(session, realm, user, OTP));
        Assert.assertFalse(BruteForceAuthChannel.isPermanentlyLocked(session, realm, user, OTP));
        Assert.assertFalse(BruteForceAuthChannel.isTemporarilyLocked(session, realm, user, null));
    }

    @Test
    public void removesOnlyTheRequestedChannelCounter() {
        RealmModel realm = realm(PASSWORD, OTP);
        UserModel user = user("user-id", "username", "user@example.com");
        Map<String, UserLoginFailureModel> failures = new HashMap<>();
        String passwordKey = BruteForceAuthChannel.getFailureKeys(realm, user, PASSWORD).get(0);
        String otpKey = BruteForceAuthChannel.getFailureKeys(realm, user, OTP).get(0);
        failures.put(passwordKey, loginFailure(1, 0));
        failures.put(otpKey, loginFailure(1, 0));
        KeycloakSession session = session(failures);

        Assert.assertTrue(BruteForceAuthChannel.removeLoginFailures(session, realm, user, PASSWORD));
        Assert.assertEquals(Set.of(otpKey), failures.keySet());
        Assert.assertFalse(BruteForceAuthChannel.removeLoginFailures(session, realm, user, PASSWORD));
        Assert.assertTrue(BruteForceAuthChannel.removeLoginFailures(session, realm, user));
        Assert.assertTrue(failures.isEmpty());
    }

    @Test
    public void rejectsAccessToAnUnprotectedChannel() {
        RealmModel realm = realm(PASSWORD);
        UserModel user = user("user-id", "username", "user@example.com");

        IllegalArgumentException cause = Assert.assertThrows(IllegalArgumentException.class,
                () -> BruteForceAuthChannel.getFailureKeys(realm, user, OTP));
        Assert.assertTrue(cause.getMessage().contains(OTP));
    }

    @Test
    public void channelKeysDoNotExposeTheCounterTheyWrap() {
        String key = BruteForceAuthChannel.channelKey(OTP, "user-id");

        Assert.assertTrue(BruteForceAuthChannel.isChannelKey(key));
        Assert.assertFalse(key.contains("user-id"));
        Assert.assertFalse(BruteForceAuthChannel.isChannelKey("user-id"));
        Assert.assertFalse(BruteForceAuthChannel.isChannelKey(null));
    }

    private static RealmModel realm(String... channels) {
        return realm(BruteForceLockPolicy.USER, BruteForceChannelLockScope.ACCOUNT, 30, null, List.of(),
                List.of(channels));
    }

    private static RealmModel realm(BruteForceLockPolicy policy, BruteForceChannelLockScope scope, int failureFactor,
            Integer channelFailureFactor, List<String> properties, List<String> channels) {
        return (RealmModel) Proxy.newProxyInstance(
                BruteForceAuthChannelTest.class.getClassLoader(),
                new Class<?>[] { RealmModel.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "getBruteForceProtectedAuthChannels" -> channels;
                    case "getBruteForceChannelLockScope" -> scope;
                    case "getBruteForceChannelFailureFactor" ->
                            channelFailureFactor != null ? channelFailureFactor : failureFactor;
                    case "getBruteForceProtectedUserProperties" -> properties;
                    case "getBruteForceLockPolicy" -> policy;
                    case "getFailureFactor", "getBruteForcePropertyFailureFactor" -> failureFactor;
                    case "isPermanentLockout" -> true;
                    case "getMaxTemporaryLockouts" -> 0;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static UserLoginFailureModel loginFailure(int failures, int failedLoginNotBefore) {
        return (UserLoginFailureModel) Proxy.newProxyInstance(
                BruteForceAuthChannelTest.class.getClassLoader(),
                new Class<?>[] { UserLoginFailureModel.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "getNumFailures" -> failures;
                    case "getNumTemporaryLockouts" -> 0;
                    case "getFailedLoginNotBefore" -> failedLoginNotBefore;
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private static KeycloakSession session(Map<String, UserLoginFailureModel> failures) {
        UserLoginFailureProvider provider = (UserLoginFailureProvider) Proxy.newProxyInstance(
                BruteForceAuthChannelTest.class.getClassLoader(),
                new Class<?>[] { UserLoginFailureProvider.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "getUserLoginFailure" -> failures.get((String) args[1]);
                    case "removeUserLoginFailure" -> failures.remove((String) args[1]);
                    default -> throw new UnsupportedOperationException(method.getName());
                });
        return (KeycloakSession) Proxy.newProxyInstance(
                BruteForceAuthChannelTest.class.getClassLoader(),
                new Class<?>[] { KeycloakSession.class },
                (proxy, method, args) -> {
                    if ("loginFailures".equals(method.getName())) {
                        return provider;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static UserModel user(String id, String username, String email) {
        return (UserModel) Proxy.newProxyInstance(
                BruteForceAuthChannelTest.class.getClassLoader(),
                new Class<?>[] { UserModel.class },
                (proxy, method, args) -> switch (method.getName()) {
                    case "getId" -> id;
                    case "getUsername" -> username;
                    case "getEmail" -> email;
                    case "getFirstName", "getLastName" -> null;
                    case "getAttributeStream" -> java.util.stream.Stream.<String>of();
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
