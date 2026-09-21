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

package org.keycloak.tests.admin;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import jakarta.ws.rs.BadRequestException;

import org.keycloak.admin.client.resource.AttackDetectionResource;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceChannelLockScope;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.InjectUser;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.oauth.OAuthClient;
import org.keycloak.testframework.oauth.annotations.InjectOAuthClient;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.realm.ManagedUser;
import org.keycloak.testframework.realm.RealmBuilder;
import org.keycloak.testframework.realm.RealmConfig;
import org.keycloak.testframework.realm.UserBuilder;
import org.keycloak.testframework.realm.UserConfig;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.awaitility.Awaitility.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@KeycloakIntegrationTest
public class AttackDetectionAuthChannelTest {

    private static final String PASSWORD_CHANNEL = "password";
    private static final String OTP_CHANNEL = "otp";
    private static final String PASSWORD = "password";

    @InjectRealm(config = BruteForceByChannelRealmConfig.class)
    ManagedRealm managedRealm;

    @InjectUser(config = ChannelUserConfig.class)
    ManagedUser user;

    @InjectOAuthClient
    OAuthClient oauthClient;

    @BeforeEach
    public void resetUserAndFailures() {
        UserRepresentation rep = user.admin().toRepresentation();
        rep.setEnabled(true);
        if (rep.getAttributes() != null) {
            rep.getAttributes().remove(UserModel.DISABLED_REASON);
        }
        user.admin().update(rep);
        managedRealm.admin().attackDetection().clearAllBruteForce();
    }

    @Test
    public void exposesStatusForEveryProtectedChannel() {
        Map<String, Object> status = managedRealm.admin().attackDetection().bruteForceUserStatus(user.getId());

        assertEquals(Set.of(PASSWORD_CHANNEL, OTP_CHANNEL), channels(status).keySet());
        assertEquals(0, channels(status).get(PASSWORD_CHANNEL).get("numFailures"));
        assertEquals(false, channels(status).get(PASSWORD_CHANNEL).get("disabled"));
    }

    @Test
    public void failedPasswordIncrementsOnlyThePasswordChannel() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();

        failPasswordLogin(2);

        assertChannelFailures(detection, PASSWORD_CHANNEL, 2);
        assertChannelFailures(detection, OTP_CHANNEL, 0);
        assertChannelLocked(detection, PASSWORD_CHANNEL, true);
        assertChannelLocked(detection, OTP_CHANNEL, false);
    }

    @Test
    public void channelScopeKeepsTheAccountUsable() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();

        failPasswordLogin(2);

        assertChannelLocked(detection, PASSWORD_CHANNEL, true);
        assertFalse((Boolean) detection.bruteForceUserStatus(user.getId()).get("disabled"));
        assertTrue(user.admin().toRepresentation().isEnabled());
    }

    @Test
    public void channelScopeDoesNotIncrementTheAccountCounter() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();

        failPasswordLogin(2);

        assertEquals(0, properties(detection.bruteForceUserStatus(user.getId())).get("id").get("numFailures"));
    }

    @Test
    public void accountScopeLocksTheWholeAccount() {
        withChannelLockScope(BruteForceChannelLockScope.ACCOUNT, () -> {
            AttackDetectionResource detection = managedRealm.admin().attackDetection();

            failPasswordLogin(2);

            assertChannelLocked(detection, PASSWORD_CHANNEL, true);
            await().atMost(10, TimeUnit.SECONDS)
                    .pollInterval(100, TimeUnit.MILLISECONDS)
                    .untilAsserted(() -> assertTrue(
                            (Boolean) detection.bruteForceUserStatus(user.getId()).get("disabled")));
        });
    }

    @Test
    public void blockedChannelRejectsTheCorrectPassword() {
        failPasswordLogin(2);

        await().atMost(10, TimeUnit.SECONDS)
                .pollInterval(100, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> assertFalse(
                        oauthClient.doPasswordGrantRequest(user.getUsername(), PASSWORD).isSuccess()));
    }

    @Test
    public void unlocksOnlyTheRequestedChannel() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();
        failPasswordLogin(2);
        assertChannelLocked(detection, PASSWORD_CHANNEL, true);

        detection.clearBruteForceForUserByChannel(user.getId(), OTP_CHANNEL);

        assertChannelLocked(detection, PASSWORD_CHANNEL, true);
        assertChannelFailures(detection, PASSWORD_CHANNEL, 2);

        detection.clearBruteForceForUserByChannel(user.getId(), PASSWORD_CHANNEL);

        assertChannelLocked(detection, PASSWORD_CHANNEL, false);
        assertChannelFailures(detection, PASSWORD_CHANNEL, 0);
    }

    @Test
    public void unlockedChannelAcceptsTheCorrectPasswordAgain() {
        failPasswordLogin(2);

        managedRealm.admin().attackDetection().clearBruteForceForUserByChannel(user.getId(), PASSWORD_CHANNEL);

        assertTrue(oauthClient.doPasswordGrantRequest(user.getUsername(), PASSWORD).isSuccess());
    }

    @Test
    public void clearForUserWithoutChannelClearsEveryChannel() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();
        failPasswordLogin(2);

        detection.clearBruteForceForUser(user.getId());

        assertChannelFailures(detection, PASSWORD_CHANNEL, 0);
        assertChannelLocked(detection, PASSWORD_CHANNEL, false);
    }

    @Test
    public void successfulLoginClearsChannelCounters() {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();
        failPasswordLogin(1);
        assertChannelFailures(detection, PASSWORD_CHANNEL, 1);

        assertTrue(oauthClient.doPasswordGrantRequest(user.getUsername(), PASSWORD).isSuccess());

        await().atMost(10, TimeUnit.SECONDS)
                .pollInterval(100, TimeUnit.MILLISECONDS)
                .untilAsserted(() -> assertChannelFailures(detection, PASSWORD_CHANNEL, 0));
    }

    @Test
    public void rejectsUnlockForAChannelThatIsNotProtected() {
        assertThrows(BadRequestException.class,
                () -> managedRealm.admin().attackDetection()
                        .clearBruteForceForUserByChannel(user.getId(), "recovery-authn-codes"));
    }

    @Test
    public void persistsChannelConfigurationInTheRealmRepresentation() {
        RealmRepresentation realm = managedRealm.admin().toRepresentation();

        assertEquals(List.of(PASSWORD_CHANNEL, OTP_CHANNEL), realm.getBruteForceProtectedAuthChannels());
        assertEquals(BruteForceChannelLockScope.CHANNEL, realm.getBruteForceChannelLockScope());
        assertEquals(2, realm.getBruteForceChannelFailureFactor());
    }

    @Test
    public void unprotectedChannelsKeepSharingTheAccountCounter() {
        withProtectedChannels(List.of(), () -> {
            AttackDetectionResource detection = managedRealm.admin().attackDetection();

            failPasswordLogin(2);

            assertTrue(channels(detection.bruteForceUserStatus(user.getId())).isEmpty());
            assertEquals(2, properties(detection.bruteForceUserStatus(user.getId())).get("id").get("numFailures"));
        });
    }

    private void failPasswordLogin(int attempts) {
        AttackDetectionResource detection = managedRealm.admin().attackDetection();
        for (int i = 0; i < attempts; i++) {
            oauthClient.doPasswordGrantRequest(user.getUsername(), "invalid");
            int expected = i + 1;
            await().atMost(10, TimeUnit.SECONDS)
                    .pollInterval(100, TimeUnit.MILLISECONDS)
                    .untilAsserted(() -> {
                        Map<String, Object> status = detection.bruteForceUserStatus(user.getId());
                        int failures = (Integer) status.get("numFailures");
                        Map<String, Map<String, Object>> channels = channels(status);
                        int channelFailures = channels.containsKey(PASSWORD_CHANNEL)
                                ? (Integer) channels.get(PASSWORD_CHANNEL).get("numFailures")
                                : 0;
                        assertTrue(failures >= expected || channelFailures >= expected
                                || Boolean.TRUE.equals(status.get("disabled")));
                    });
        }
    }

    private void withProtectedChannels(List<String> channels, Runnable test) {
        RealmRepresentation realm = managedRealm.admin().toRepresentation();
        List<String> previous = List.copyOf(realm.getBruteForceProtectedAuthChannels());
        realm.setBruteForceProtectedAuthChannels(channels);
        managedRealm.admin().update(realm);
        try {
            test.run();
        } finally {
            RealmRepresentation restore = managedRealm.admin().toRepresentation();
            restore.setBruteForceProtectedAuthChannels(previous);
            managedRealm.admin().update(restore);
        }
    }

    private void withChannelLockScope(BruteForceChannelLockScope scope, Runnable test) {
        RealmRepresentation realm = managedRealm.admin().toRepresentation();
        BruteForceChannelLockScope previous = realm.getBruteForceChannelLockScope();
        realm.setBruteForceChannelLockScope(scope);
        managedRealm.admin().update(realm);
        try {
            test.run();
        } finally {
            RealmRepresentation restore = managedRealm.admin().toRepresentation();
            restore.setBruteForceChannelLockScope(previous);
            managedRealm.admin().update(restore);
        }
    }

    private void assertChannelLocked(AttackDetectionResource detection, String channel, boolean expected) {
        assertEquals(expected,
                channels(detection.bruteForceUserStatus(user.getId())).get(channel).get("disabled"));
    }

    private void assertChannelFailures(AttackDetectionResource detection, String channel, int expected) {
        assertEquals(expected,
                channels(detection.bruteForceUserStatus(user.getId())).get(channel).get("numFailures"));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> channels(Map<String, Object> status) {
        return (Map<String, Map<String, Object>>) status.get("channels");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> properties(Map<String, Object> status) {
        return (Map<String, Map<String, Object>>) status.get("properties");
    }

    public static class BruteForceByChannelRealmConfig implements RealmConfig {

        @Override
        public RealmBuilder configure(RealmBuilder realm) {
            return realm.bruteForceProtected(true)
                    .failureFactor(30)
                    .bruteForceChannelFailureFactor(2)
                    .bruteForceChannelLockScope(BruteForceChannelLockScope.CHANNEL)
                    .bruteForceProtectedAuthChannels(PASSWORD_CHANNEL, OTP_CHANNEL)
                    .waitIncrementSeconds(60)
                    .quickLoginCheckMilliSeconds(0);
        }
    }

    public static class ChannelUserConfig implements UserConfig {

        @Override
        public UserBuilder configure(UserBuilder user) {
            return user.username("channel-user")
                    .name("Channel", "User")
                    .email("channel-user@example.com")
                    .emailVerified(true)
                    .password(PASSWORD);
        }
    }
}
