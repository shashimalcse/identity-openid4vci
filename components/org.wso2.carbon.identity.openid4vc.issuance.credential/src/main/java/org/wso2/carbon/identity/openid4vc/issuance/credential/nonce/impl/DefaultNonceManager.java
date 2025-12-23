/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.credential.cache.NonceCache;
import org.wso2.carbon.identity.openid4vc.issuance.credential.cache.NonceCacheEntry;
import org.wso2.carbon.identity.openid4vc.issuance.credential.cache.NonceCacheKey;
import org.wso2.carbon.identity.openid4vc.issuance.credential.cache.NonceEntry;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.NonceManager;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Default implementation of NonceManager use cache to store nonces with expiration.
 * <p>
 * Uses ConcurrentHashMap for thread-safe nonce storage with automatic
 * expiration tracking. Suitable for single-node deployments.
 * For clustered deployments, consider using Redis or database-backed storage.
 */
public class DefaultNonceManager implements NonceManager {

    private static final Log LOG = LogFactory.getLog(DefaultNonceManager.class);

    private static final int NONCE_LENGTH_BYTES = 16;
    private static final int DEFAULT_EXPIRATION_SECONDS = 300; // 5 minutes

    private final SecureRandom secureRandom;
    private final NonceCache nonceCache;
    private final int expirationSeconds;

    /**
     * Create an DefaultNonceManager with default expiration time.
     */
    public DefaultNonceManager() {

        this(DEFAULT_EXPIRATION_SECONDS);
    }

    /**
     * Create an DefaultNonceManager with custom expiration time.
     *
     * @param expirationSeconds nonce expiration time in seconds
     */
    public DefaultNonceManager(int expirationSeconds) {

        this.secureRandom = new SecureRandom();
        this.expirationSeconds = expirationSeconds;

        this.nonceCache = NonceCache.getInstance();

        if (LOG.isDebugEnabled()) {
            LOG.debug("DefaultNonceManager initialized with expiration: " + expirationSeconds + "s");
        }
    }

    @Override
    public String generateNonce(String tenantDomain) throws CredentialIssuanceException {

        byte[] nonceBytes = new byte[NONCE_LENGTH_BYTES];
        secureRandom.nextBytes(nonceBytes);
        String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(nonceBytes);

        long expiresAt = System.currentTimeMillis() + TimeUnit.SECONDS.toMillis(expirationSeconds);
        NonceCacheKey cacheKey = new NonceCacheKey(nonce);
        NonceEntry nonceEntry = new NonceEntry(expiresAt, tenantDomain);
        nonceCache.addToCache(cacheKey, new NonceCacheEntry(nonceEntry), tenantDomain);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Generated nonce for tenant: " + tenantDomain);
        }

        return nonce;
    }

    @Override
    public boolean validateAndConsumeNonce(String nonce, String tenantDomain)
            throws CredentialIssuanceException {

        if (nonce == null || nonce.isEmpty()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Nonce validation failed: nonce is null or empty");
            }
            return false;
        }

        NonceCacheKey cacheKey = new NonceCacheKey(nonce);
        NonceCacheEntry cacheEntry = nonceCache.getValueFromCache(cacheKey, tenantDomain);
        if (cacheEntry == null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Nonce not found or already used");
            }
            return false;
        }
        NonceEntry nonceEntry = cacheEntry.getNonceEntry();

        // Remove nonce from cache to prevent reuse
        nonceCache.clearCacheEntry(cacheKey, tenantDomain);

        if (nonceEntry.isExpired()) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Nonce validation failed: nonce expired");
            }
            return false;
        }

        // Verify tenant domain matches
        if (!tenantDomain.equals(nonceEntry.getTenantDomain())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Nonce validation failed: tenant domain mismatch");
            }
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Nonce validated and consumed for tenant: " + tenantDomain);
        }

        return true;
    }

    @Override
    public int getNonceExpiresIn() {

        return expirationSeconds;
    }
}
