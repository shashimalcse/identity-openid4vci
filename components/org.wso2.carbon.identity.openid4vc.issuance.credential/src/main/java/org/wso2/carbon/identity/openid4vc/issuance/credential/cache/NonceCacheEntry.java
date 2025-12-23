package org.wso2.carbon.identity.openid4vc.issuance.credential.cache;

import org.wso2.carbon.identity.core.cache.CacheEntry;

/**
 * Cache entry for nonce entries.
 */
public class NonceCacheEntry extends CacheEntry {

    private NonceEntry nonceEntry;

    public NonceCacheEntry(NonceEntry nonceEntry) {

        this.nonceEntry = nonceEntry;
    }

    public NonceEntry getNonceEntry() {

        return nonceEntry;
    }

    public void setNonceEntry(NonceEntry nonceEntry) {

        this.nonceEntry = nonceEntry;
    }
}
