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

package org.wso2.carbon.identity.openid4vc.issuance.credential.proof;

import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;

import java.util.List;
import java.util.Map;

/**
 * Service for validating proof of possession in credential requests.
 */
public interface ProofValidationService {

    /**
     * Validate proofs and extract public key.
     *
     * @param proofs           map of proof type to proof values
     * @param issuerIdentifier the credential issuer identifier
     * @param tenantDomain     the tenant domain
     * @return validated proof DTO containing the holder's public key
     * @throws CredentialIssuanceException if validation fails
     */
    ProofDTO validateProof(Map<String, List<String>> proofs,
            String issuerIdentifier,
            String tenantDomain)
            throws CredentialIssuanceException;
}
