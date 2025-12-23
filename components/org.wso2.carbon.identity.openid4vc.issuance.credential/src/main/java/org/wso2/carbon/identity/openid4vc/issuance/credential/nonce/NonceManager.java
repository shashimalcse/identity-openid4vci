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

package org.wso2.carbon.identity.openid4vc.issuance.credential.nonce;

import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

/**
 * Manager for server-generated nonces (c_nonce) used in proof validation.
 */
public interface NonceManager {

    /**
     * Generate a new cryptographically secure nonce.
     *
     * @param tenantDomain the tenant domain for multi-tenant support
     * @return the generated nonce string
     * @throws CredentialIssuanceException if nonce generation fails
     */
    String generateNonce(String tenantDomain) throws CredentialIssuanceException;

    /**
     * Validate and consume a nonce.
     * This checks that the nonce exists, is unexpired, and hasn't been used before.
     * If valid, it marks the nonce as consumed to prevent reuse.
     *
     * @param nonce        the nonce to validate
     * @param tenantDomain the tenant domain for multi-tenant support
     * @return true if the nonce is valid and successfully consumed
     * @throws CredentialIssuanceException if validation fails or an error occurs
     */
    boolean validateAndConsumeNonce(String nonce, String tenantDomain)
            throws CredentialIssuanceException;

    /**
     * Get the nonce expiration time in seconds.
     *
     * @return expiration time in seconds
     */
    int getNonceExpiresIn();
}
