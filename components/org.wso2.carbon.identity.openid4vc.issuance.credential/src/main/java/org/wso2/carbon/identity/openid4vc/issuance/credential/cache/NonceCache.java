package org.wso2.carbon.identity.openid4vc.issuance.credential.cache;

import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.utils.CarbonUtils;

/**
 * Cache to store nonces used in OpenID4VC credential issuance.
 */
public class NonceCache extends BaseCache<NonceCacheKey, NonceCacheEntry> {

    private static final String NONCE_CACHE_NAME = "openid4vc.issuance.credential.nonce.cache";

    private static final NonceCache INSTANCE = new NonceCache();

    private NonceCache() {

        super(NONCE_CACHE_NAME);
    }

    /**
     * Retrieve the singleton instance of NonceCache.
     *
     * @return NonceCache instance.
     */
    public static NonceCache getInstance() {

        CarbonUtils.checkSecurity();
        return INSTANCE;
    }
}
