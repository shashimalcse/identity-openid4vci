package org.wso2.carbon.identity.openid4vc.issuance.credential.cache;

import org.wso2.carbon.identity.core.cache.CacheKey;

/**
 * Cache key for nonce entries.
 */
public class NonceCacheKey extends CacheKey {

    private final String nonce;

    public NonceCacheKey(String nonce) {

        this.nonce = nonce;
    }

    public String getNonce() {

        return nonce;
    }

    @Override
    public boolean equals(Object o) {

        if (!(o instanceof NonceCacheKey)) {
            return false;
        }
        return nonce.equals(((NonceCacheKey) o).getNonce());
    }

    @Override
    public int hashCode() {

        return nonce.hashCode();
    }
}
