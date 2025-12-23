package org.wso2.carbon.identity.openid4vc.issuance.credential.cache;

/**
 * Represents a nonce entry with expiration and tenant domain information.
 */
public class NonceEntry {

    private final long expiresAt;
    private final String tenantDomain;

    public NonceEntry(long expiresAt, String tenantDomain) {

        this.expiresAt = expiresAt;
        this.tenantDomain = tenantDomain;
    }

    public boolean isExpired() {

        return System.currentTimeMillis() > expiresAt;
    }

    public String getTenantDomain() {

        return tenantDomain;
    }
}
