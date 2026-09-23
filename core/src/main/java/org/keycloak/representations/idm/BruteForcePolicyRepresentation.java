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
package org.keycloak.representations.idm;

/**
 * Optional overrides for one protected user property's brute-force policy.
 *
 * <p>Every {@code null} field inherits the corresponding realm setting. The failure factor first
 * falls back to the realm's property failure factor, which in turn falls back to the account
 * failure factor.</p>
 */
public class BruteForcePolicyRepresentation {

    protected Boolean permanentLockout;
    protected Integer maxTemporaryLockouts;
    protected RealmRepresentation.BruteForceStrategy bruteForceStrategy;
    protected Integer maxFailureWaitSeconds;
    protected Integer minimumQuickLoginWaitSeconds;
    protected Integer waitIncrementSeconds;
    protected Long quickLoginCheckMilliSeconds;
    protected Integer maxDeltaTimeSeconds;
    protected Integer failureFactor;

    public Boolean isPermanentLockout() {
        return permanentLockout;
    }

    public void setPermanentLockout(Boolean permanentLockout) {
        this.permanentLockout = permanentLockout;
    }

    public Integer getMaxTemporaryLockouts() {
        return maxTemporaryLockouts;
    }

    public void setMaxTemporaryLockouts(Integer maxTemporaryLockouts) {
        this.maxTemporaryLockouts = maxTemporaryLockouts;
    }

    public RealmRepresentation.BruteForceStrategy getBruteForceStrategy() {
        return bruteForceStrategy;
    }

    public void setBruteForceStrategy(RealmRepresentation.BruteForceStrategy bruteForceStrategy) {
        this.bruteForceStrategy = bruteForceStrategy;
    }

    public Integer getMaxFailureWaitSeconds() {
        return maxFailureWaitSeconds;
    }

    public void setMaxFailureWaitSeconds(Integer maxFailureWaitSeconds) {
        this.maxFailureWaitSeconds = maxFailureWaitSeconds;
    }

    public Integer getMinimumQuickLoginWaitSeconds() {
        return minimumQuickLoginWaitSeconds;
    }

    public void setMinimumQuickLoginWaitSeconds(Integer minimumQuickLoginWaitSeconds) {
        this.minimumQuickLoginWaitSeconds = minimumQuickLoginWaitSeconds;
    }

    public Integer getWaitIncrementSeconds() {
        return waitIncrementSeconds;
    }

    public void setWaitIncrementSeconds(Integer waitIncrementSeconds) {
        this.waitIncrementSeconds = waitIncrementSeconds;
    }

    public Long getQuickLoginCheckMilliSeconds() {
        return quickLoginCheckMilliSeconds;
    }

    public void setQuickLoginCheckMilliSeconds(Long quickLoginCheckMilliSeconds) {
        this.quickLoginCheckMilliSeconds = quickLoginCheckMilliSeconds;
    }

    public Integer getMaxDeltaTimeSeconds() {
        return maxDeltaTimeSeconds;
    }

    public void setMaxDeltaTimeSeconds(Integer maxDeltaTimeSeconds) {
        this.maxDeltaTimeSeconds = maxDeltaTimeSeconds;
    }

    public Integer getFailureFactor() {
        return failureFactor;
    }

    public void setFailureFactor(Integer failureFactor) {
        this.failureFactor = failureFactor;
    }
}
