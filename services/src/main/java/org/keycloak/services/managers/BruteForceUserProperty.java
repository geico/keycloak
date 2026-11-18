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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Stream;

import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.Time;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserLoginFailureModel;
import org.keycloak.models.UserModel;

/**
 * Resolves brute-force failure-counter keys for a user.
 *
 * <p>The realm {@link org.keycloak.representations.idm.RealmRepresentation.BruteForceLockPolicy}
 * decides whether login is locked by the per-user id counter or by selected user properties.
 * Failed attempts increment the user-id counter or the submitted
 * identifier's property counter. The user-id threshold disables every identifier for that
 * account. A property threshold blocks only attempts that reuse that property value, so a
 * locked email does not block a phone number or username that still has remaining attempts.
 * Property counters are shared by every user with the same property value. Counter keys
 * store a digest of the value rather than the raw attribute.</p>
 */
public final class BruteForceUserProperty {

    public static final String ID = "id";
    private static final String PROPERTY_KEY_PREFIX = "bf-property:";

    private BruteForceUserProperty() {
    }

    public static List<String> getFailureKeys(RealmModel realm, UserModel user) {
        Set<String> keys = new LinkedHashSet<>();
        for (String property : getProtectedProperties(realm)) {
            keys.addAll(getFailureKeys(realm, user, property));
        }
        return List.copyOf(keys);
    }

    /**
     * Counters to increment for this login attempt. {@code USER} always uses the user id.
     * {@code PROPERTIES} increments only property counters whose current value matches
     * {@code attemptedIdentifier}.
     */
    public static List<String> getFailureKeysForAttempt(RealmModel realm, UserModel user, String attemptedIdentifier) {
        String identifier = attemptedIdentifier == null || attemptedIdentifier.isBlank()
                ? user.getUsername()
                : attemptedIdentifier;
        return switch (realm.getBruteForceLockPolicy()) {
            case PROPERTIES -> getMatchingPropertyKeys(realm, user, identifier);
            case USER -> List.of(user.getId());
        };
    }

    /**
     * Property counters that match {@code attemptedIdentifier}. When the identifier is blank, or
     * matches none of the protected properties (for example it was resolved through a property that
     * is not protected), the user's username counter is used instead so a failed attempt is
     * never left without a counter.
     */
    public static List<String> getMatchingPropertyKeys(RealmModel realm, UserModel user, String attemptedIdentifier) {
        String identifier = attemptedIdentifier == null || attemptedIdentifier.isBlank()
                ? user.getUsername()
                : attemptedIdentifier;
        List<String> keys = matchPropertyKeys(realm, user, identifier);
        if (keys.isEmpty() && user.getUsername() != null && !user.getUsername().isBlank()) {
            keys = List.of(propertyKey(UserModel.USERNAME, normalize(UserModel.USERNAME, user.getUsername())));
        }
        return keys;
    }

    private static List<String> matchPropertyKeys(RealmModel realm, UserModel user, String attemptedIdentifier) {
        Set<String> keys = new LinkedHashSet<>();
        for (String property : getProtectedProperties(realm)) {
            if (ID.equals(property)) {
                keys.add(user.getId());
                continue;
            }
            String attempted = normalize(property, attemptedIdentifier);
            values(user, property)
                    .filter(value -> value != null && !value.isBlank())
                    .map(value -> normalize(property, value))
                    .filter(attempted::equals)
                    .map(value -> propertyKey(property, value))
                    .forEach(keys::add);
        }
        return List.copyOf(keys);
    }

    /**
     * Counters that disable every identifier of this user. Property keys are omitted so a
     * locked email or phone number cannot disable login with a different identifier.
     */
    public static List<String> getAccountLockKeys(RealmModel realm, UserModel user) {
        if (!getProtectedProperties(realm).contains(ID)) {
            return List.of();
        }
        return List.of(user.getId());
    }

    public static boolean isPropertyKey(String failureKey) {
        return failureKey != null && failureKey.startsWith(PROPERTY_KEY_PREFIX);
    }

    /**
     * Find users by a protected custom attribute such as {@code phoneNumber} after username
     * and email lookup missed. Built-in username and email are left to
     * {@link org.keycloak.models.utils.KeycloakModelUtils#findUserByNameOrEmail}. Several users
     * may share a property value; at most two distinct users are returned, which is enough to
     * tell a unique match from an ambiguous one without scanning every match.
     */
    public static List<UserModel> findUsersByProtectedPropertyValue(KeycloakSession session, RealmModel realm,
            String identifier) {
        if (identifier == null || identifier.isBlank()) {
            return List.of();
        }
        Map<String, UserModel> users = new LinkedHashMap<>();
        for (String property : realm.getBruteForceProtectedUserProperties()) {
            if (users.size() > 1) {
                break;
            }
            if (ID.equals(property) || UserModel.USERNAME.equals(property) || UserModel.EMAIL.equals(property)) {
                continue;
            }
            try (Stream<UserModel> found = findUsersByPropertyValue(session, realm, property, identifier)) {
                found.limit(2).forEach(user -> users.putIfAbsent(user.getId(), user));
            }
        }
        return List.copyOf(users.values());
    }

    /**
     * Find the single user that has a protected custom attribute value.
     *
     * @throws ModelDuplicateException when several users share the value, as the login cannot
     *         tell which account is being authenticated
     */
    public static UserModel findUserByProtectedPropertyValue(KeycloakSession session, RealmModel realm,
            String identifier) {
        List<UserModel> users = findUsersByProtectedPropertyValue(session, realm, identifier);
        if (users.size() > 1) {
            throw new ModelDuplicateException("Multiple users match protected property value");
        }
        return users.isEmpty() ? null : users.get(0);
    }

    public static boolean isPermanentlyLocked(RealmModel realm, UserLoginFailureModel model) {
        return realm.isPermanentLockout()
                && (model.getNumTemporaryLockouts() > realm.getMaxTemporaryLockouts()
                || (realm.getMaxTemporaryLockouts() == 0
                && model.getNumFailures() >= realm.getFailureFactor()));
    }

    public static List<String> getProtectedProperties(RealmModel realm) {
        Set<String> properties = new LinkedHashSet<>();
        switch (realm.getBruteForceLockPolicy()) {
            case PROPERTIES -> {
                properties.addAll(realm.getBruteForceProtectedUserProperties());
                if (properties.isEmpty()) {
                    properties.add(ID);
                } else if (!properties.contains(ID)) {
                    // The username counter is the fallback for attempts that match no configured
                    // property, so a narrow property list cannot leave a failed attempt uncounted.
                    properties.add(UserModel.USERNAME);
                }
            }
            case USER -> properties.add(ID);
        }
        return List.copyOf(properties);
    }

    public static List<String> getFailureKeys(RealmModel realm, UserModel user, String property) {
        if (!getProtectedProperties(realm).contains(property)) {
            throw new IllegalArgumentException("User property is not protected by brute force detection: " + property);
        }
        if (ID.equals(property)) {
            return List.of(user.getId());
        }

        return values(user, property)
                .filter(value -> value != null && !value.isBlank())
                .map(value -> propertyKey(property, normalize(property, value)))
                .distinct()
                .toList();
    }

    public static boolean removeLoginFailures(KeycloakSession session, RealmModel realm, UserModel user) {
        boolean removed = false;
        for (String failureKey : getFailureKeys(realm, user)) {
            if (session.loginFailures().getUserLoginFailure(realm, failureKey) != null) {
                session.loginFailures().removeUserLoginFailure(realm, failureKey);
                removed = true;
            }
        }
        return removed;
    }

    /**
     * Removes the property counters of a user that is being deleted. Counters are keyed by the
     * property value, not the user, so a counter is kept while another user still has the same
     * value. Call before the user is removed so its values can still be read.
     */
    public static void removePropertyLoginFailures(KeycloakSession session, RealmModel realm, UserModel user) {
        for (String property : getProtectedProperties(realm)) {
            if (!ID.equals(property)) {
                removeUnusedPropertyCounters(session, realm, user, property, values(user, property).toList());
            }
        }
    }

    /**
     * Removes the counters of {@code oldValues} of a protected property that a user no longer has,
     * for example after an email change. Without this the counter would linger, and a permanent
     * lock on it could never be cleared because unlocking only visits a user's current values.
     * A counter is kept while the user or another user still has the value.
     */
    public static void removePropertyLoginFailures(KeycloakSession session, RealmModel realm, UserModel user,
            String property, List<String> oldValues) {
        if (ID.equals(property) || !getProtectedProperties(realm).contains(property)) {
            return;
        }
        Set<String> current = values(user, property)
                .filter(v -> v != null && !v.isBlank())
                .map(v -> normalize(property, v))
                .collect(java.util.stream.Collectors.toSet());
        removeUnusedPropertyCounters(session, realm, user, property, oldValues.stream()
                .filter(v -> v != null && !v.isBlank() && !current.contains(normalize(property, v))).toList());
    }

    private static void removeUnusedPropertyCounters(KeycloakSession session, RealmModel realm, UserModel user,
            String property, List<String> oldValues) {
        for (String value : oldValues.stream().filter(v -> v != null && !v.isBlank()).distinct().toList()) {
            if (isValueUsedByAnotherUser(session, realm, user, property, value)) {
                continue;
            }
            String failureKey = propertyKey(property, normalize(property, value));
            if (session.loginFailures().getUserLoginFailure(realm, failureKey) != null) {
                session.loginFailures().removeUserLoginFailure(realm, failureKey);
            }
        }
    }

    private static boolean isValueUsedByAnotherUser(KeycloakSession session, RealmModel realm, UserModel user,
            String property, String value) {
        Stream<UserModel> others = switch (property) {
            case UserModel.USERNAME -> Stream.empty();
            case UserModel.EMAIL, UserModel.FIRST_NAME, UserModel.LAST_NAME -> session.users()
                    .searchForUserStream(realm, Map.of(property, value, UserModel.EXACT, Boolean.TRUE.toString()));
            default -> findUsersByPropertyValue(session, realm, property, value);
        };
        try (others) {
            return others.anyMatch(other -> !other.getId().equals(user.getId()));
        }
    }

    public static Stream<UserLoginFailureModel> getLoginFailures(KeycloakSession session, RealmModel realm,
            UserModel user) {
        return getFailureKeys(realm, user).stream()
                .map(failureKey -> session.loginFailures().getUserLoginFailure(realm, failureKey))
                .filter(Objects::nonNull);
    }

    /**
     * Whether any counter of this user currently blocks a login attempt. Unlike
     * {@link BruteForceProtector#isTemporarilyDisabled}, this includes property counters, which
     * block only the identifier they belong to rather than the whole account.
     */
    public static boolean isLocked(KeycloakSession session, RealmModel realm, UserModel user) {
        int currentTime = Time.currentTime();
        for (String failureKey : getFailureKeys(realm, user)) {
            UserLoginFailureModel model = session.loginFailures().getUserLoginFailure(realm, failureKey);
            if (model != null && (currentTime < model.getFailedLoginNotBefore()
                    || isPermanentlyLocked(realm, model))) {
                return true;
            }
        }
        return false;
    }

    static String propertyKey(String property, String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest((property + '\0' + value).getBytes(StandardCharsets.UTF_8));
            return PROPERTY_KEY_PREFIX + Base64Url.encode(bytes);
        } catch (NoSuchAlgorithmException cause) {
            throw new IllegalStateException("SHA-256 is not available", cause);
        }
    }

    private static Stream<UserModel> findUsersByPropertyValue(KeycloakSession session, RealmModel realm,
            String property, String value) {
        return session.users().searchForUserByUserAttributeStream(realm, property, value);
    }

    private static Stream<String> values(UserModel user, String property) {
        return switch (property) {
            case UserModel.USERNAME -> Stream.ofNullable(user.getUsername());
            case UserModel.EMAIL -> Stream.ofNullable(user.getEmail());
            case UserModel.FIRST_NAME -> Stream.ofNullable(user.getFirstName());
            case UserModel.LAST_NAME -> Stream.ofNullable(user.getLastName());
            default -> user.getAttributeStream(property);
        };
    }

    private static String normalize(String property, String value) {
        String normalized = value.trim();
        return switch (property) {
            case UserModel.USERNAME, UserModel.EMAIL -> normalized.toLowerCase(Locale.ROOT);
            default -> normalized;
        };
    }
}
