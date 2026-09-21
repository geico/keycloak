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

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.RealmRepresentation.BruteForceChannelLockScope;

/**
 * Resolves brute-force failure-counter keys for an individual authentication channel.
 *
 * <p>A channel is the reference category of the authenticator that failed, which is the credential
 * type it verifies ({@code password}, {@code otp}, {@code recovery-authn-codes}, or the category
 * declared by a custom authenticator such as an SMS or email OTP form). Channels listed in
 * {@link RealmModel#getBruteForceProtectedAuthChannels()} get their own failure counter on top of
 * the account and user-property counters, so attempts against one channel do not consume the
 * budget of another.</p>
 *
 * <p>{@link RealmModel#getBruteForceChannelLockScope()} decides what happens when a channel
 * reaches {@link RealmModel#getBruteForceChannelFailureFactor()}: {@code ACCOUNT} disables login
 * entirely, {@code CHANNEL} blocks only further attempts on that channel. Channel keys wrap the
 * account or property key they belong to, so a shared property value keeps sharing its channel
 * counters.</p>
 */
public final class BruteForceAuthChannel {

    private static final String CHANNEL_KEY_PREFIX = "bf-channel:";

    private BruteForceAuthChannel() {
    }

    /**
     * Channels that maintain their own counter. Empty when the realm has not opted in, which keeps
     * every channel sharing the account counter as before.
     */
    public static List<String> getProtectedChannels(RealmModel realm) {
        return realm.getBruteForceProtectedAuthChannels().stream()
                .map(BruteForceAuthChannel::normalize)
                .filter(channel -> !channel.isEmpty())
                .distinct()
                .toList();
    }

    public static boolean isProtected(RealmModel realm, String channel) {
        return channel != null && getProtectedChannels(realm).contains(normalize(channel));
    }

    /**
     * The protected channel this attempt belongs to, or {@code null} when the attempt is not tracked
     * separately. Authenticators report a single category per execution; the first protected match
     * wins so a flow that reports several categories still increments one channel counter.
     */
    public static String resolveChannel(RealmModel realm, Set<String> authenticationCategories) {
        if (authenticationCategories == null || authenticationCategories.isEmpty()) {
            return null;
        }
        List<String> protectedChannels = getProtectedChannels(realm);
        if (protectedChannels.isEmpty()) {
            return null;
        }
        return authenticationCategories.stream()
                .filter(Objects::nonNull)
                .map(BruteForceAuthChannel::normalize)
                .filter(protectedChannels::contains)
                .findFirst()
                .orElse(null);
    }

    /**
     * Whether a channel that reached its threshold disables the whole account. When this is
     * {@code false}, channel failures are kept out of the account counters so the remaining
     * channels stay usable.
     */
    public static boolean locksAccount(RealmModel realm) {
        return realm.getBruteForceChannelLockScope() == BruteForceChannelLockScope.ACCOUNT;
    }

    public static boolean isChannelKey(String failureKey) {
        return failureKey != null && failureKey.startsWith(CHANNEL_KEY_PREFIX);
    }

    /**
     * Counters to increment for a failed attempt on {@code channel}. One key per base key, so the
     * lock policy still decides whether the attempt counts against the account, the submitted
     * identifier, or both.
     */
    public static List<String> getFailureKeysForAttempt(RealmModel realm, UserModel user, String channel,
            String attemptedIdentifier) {
        return toChannelKeys(channel,
                BruteForceUserProperty.getFailureKeysForAttempt(realm, user, attemptedIdentifier));
    }

    public static List<String> getFailureKeys(RealmModel realm, UserModel user, String channel) {
        if (!isProtected(realm, channel)) {
            throw new IllegalArgumentException("Authentication channel is not protected by brute force detection: " + channel);
        }
        return toChannelKeys(channel, BruteForceUserProperty.getFailureKeys(realm, user));
    }

    /**
     * Every channel counter of this user, for status reporting and cleanup.
     */
    public static List<String> getAllFailureKeys(RealmModel realm, UserModel user) {
        return getFailureKeysForBaseKeys(realm, BruteForceUserProperty.getFailureKeys(realm, user));
    }

    /**
     * Channel counters layered on top of the given account or property counters. Used when clearing
     * a single property, which must also clear that property's per-channel counters.
     */
    public static List<String> getFailureKeysForBaseKeys(RealmModel realm, List<String> baseKeys) {
        Set<String> keys = new LinkedHashSet<>();
        for (String channel : getProtectedChannels(realm)) {
            keys.addAll(toChannelKeys(channel, baseKeys));
        }
        return List.copyOf(keys);
    }

    public static Stream<UserLoginFailureModel> getLoginFailures(KeycloakSession session, RealmModel realm,
            UserModel user, String channel) {
        return getFailureKeys(realm, user, channel).stream()
                .map(failureKey -> session.loginFailures().getUserLoginFailure(realm, failureKey))
                .filter(Objects::nonNull);
    }

    public static Stream<UserLoginFailureModel> getLoginFailures(KeycloakSession session, RealmModel realm,
            UserModel user) {
        return getAllFailureKeys(realm, user).stream()
                .map(failureKey -> session.loginFailures().getUserLoginFailure(realm, failureKey))
                .filter(Objects::nonNull);
    }

    public static boolean removeLoginFailures(KeycloakSession session, RealmModel realm, UserModel user) {
        return removeFailureKeys(session, realm, getAllFailureKeys(realm, user));
    }

    public static boolean removeLoginFailures(KeycloakSession session, RealmModel realm, UserModel user,
            String channel) {
        return removeFailureKeys(session, realm, getFailureKeys(realm, user, channel));
    }

    /**
     * Whether {@code channel} is temporarily blocked by its own counter. Callers must also check the
     * account counters, which block every channel.
     */
    public static boolean isTemporarilyLocked(KeycloakSession session, RealmModel realm, UserModel user,
            String channel) {
        if (!isProtected(realm, channel)) {
            return false;
        }
        int currentTime = Time.currentTime();
        return failures(session, realm, user, channel)
                .anyMatch(model -> currentTime < model.getFailedLoginNotBefore());
    }

    /**
     * Whether {@code channel} exhausted its attempts for good. The user account stays enabled, so
     * this only blocks further attempts on that channel.
     */
    public static boolean isPermanentlyLocked(KeycloakSession session, RealmModel realm, UserModel user,
            String channel) {
        if (!isProtected(realm, channel) || !realm.isPermanentLockout()) {
            return false;
        }
        for (String failureKey : getFailureKeys(realm, user, channel)) {
            UserLoginFailureModel model = session.loginFailures().getUserLoginFailure(realm, failureKey);
            if (model != null && BruteForceUserProperty.isPermanentlyLocked(realm, model, failureKey)) {
                return true;
            }
        }
        return false;
    }

    private static Stream<UserLoginFailureModel> failures(KeycloakSession session, RealmModel realm, UserModel user,
            String channel) {
        return getFailureKeys(realm, user, channel).stream()
                .map(failureKey -> session.loginFailures().getUserLoginFailure(realm, failureKey))
                .filter(Objects::nonNull);
    }

    static String channelKey(String channel, String baseKey) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest((normalize(channel) + '\0' + baseKey).getBytes(StandardCharsets.UTF_8));
            return CHANNEL_KEY_PREFIX + Base64Url.encode(bytes);
        } catch (NoSuchAlgorithmException cause) {
            throw new IllegalStateException("SHA-256 is not available", cause);
        }
    }

    private static List<String> toChannelKeys(String channel, List<String> baseKeys) {
        Set<String> keys = new LinkedHashSet<>();
        for (String baseKey : baseKeys) {
            keys.add(channelKey(channel, baseKey));
        }
        return List.copyOf(keys);
    }

    private static boolean removeFailureKeys(KeycloakSession session, RealmModel realm, List<String> failureKeys) {
        boolean removed = false;
        for (String failureKey : failureKeys) {
            if (session.loginFailures().getUserLoginFailure(realm, failureKey) != null) {
                session.loginFailures().removeUserLoginFailure(realm, failureKey);
                removed = true;
            }
        }
        return removed;
    }

    private static String normalize(String channel) {
        return channel == null ? "" : channel.trim().toLowerCase(Locale.ROOT);
    }
}
