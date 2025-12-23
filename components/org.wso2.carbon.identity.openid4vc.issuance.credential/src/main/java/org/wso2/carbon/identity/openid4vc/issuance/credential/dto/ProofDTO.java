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

package org.wso2.carbon.identity.openid4vc.issuance.credential.dto;

import java.util.Map;

/**
 * DTO representing a validated proof of possession.
 */
public class ProofDTO {

    private String proofType;
    private Map<String, Object> publicKey;
    private String keyId;
    private long issuedAt;
    private String nonce;

    public String getProofType() {

        return proofType;
    }

    public void setProofType(String proofType) {

        this.proofType = proofType;
    }

    public Map<String, Object> getPublicKey() {

        return publicKey;
    }

    public void setPublicKey(Map<String, Object> publicKey) {

        this.publicKey = publicKey;
    }

    public String getKeyId() {

        return keyId;
    }

    public void setKeyId(String keyId) {

        this.keyId = keyId;
    }

    public long getIssuedAt() {

        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {

        this.issuedAt = issuedAt;
    }

    public String getNonce() {

        return nonce;
    }

    public void setNonce(String nonce) {

        this.nonce = nonce;
    }
}
