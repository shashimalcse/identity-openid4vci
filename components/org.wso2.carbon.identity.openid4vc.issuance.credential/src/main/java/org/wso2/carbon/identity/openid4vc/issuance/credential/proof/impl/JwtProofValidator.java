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

package org.wso2.carbon.identity.openid4vc.issuance.credential.proof.impl;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vc.issuance.credential.dto.ProofDTO;
import org.wso2.carbon.identity.openid4vc.issuance.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vc.issuance.credential.nonce.NonceManager;
import org.wso2.carbon.identity.openid4vc.issuance.credential.proof.ProofValidationService;

import java.util.List;
import java.util.Map;

/**
 * JWT proof validation implementation.
 */
public class JwtProofValidator implements ProofValidationService {

    private static final Log LOG = LogFactory.getLog(JwtProofValidator.class);

    private static final String PROOF_TYPE_JWT = "jwt";
    private static final String EXPECTED_TYP = "openid4vci-proof+jwt";
    private static final long MAX_CLOCK_SKEW_SECONDS = 60;

    private final NonceManager nonceManager;

    public JwtProofValidator(NonceManager nonceManager) {

        this.nonceManager = nonceManager;
    }

    @Override
    public ProofDTO validateProof(Map<String, List<String>> proofs,
            String issuerIdentifier,
            String tenantDomain)
            throws CredentialIssuanceException {

        // Check proof type exists
        if (!proofs.containsKey(PROOF_TYPE_JWT)) {
            throw new CredentialIssuanceException("Only JWT proof type is supported");
        }

        List<String> jwtProofs = proofs.get(PROOF_TYPE_JWT);
        if (jwtProofs == null || jwtProofs.isEmpty()) {
            throw new CredentialIssuanceException("JWT proof is required");
        }

        // Enforce single proof for single credential issuance
        if (jwtProofs.size() > 1) {
            throw new CredentialIssuanceException(
                    "Multiple proofs not supported for single credential issuance");
        }

        String jwtString = jwtProofs.get(0);
        return validateJwtProof(jwtString, issuerIdentifier, tenantDomain);
    }

    private ProofDTO validateJwtProof(String jwtString,
            String issuerIdentifier,
            String tenantDomain)
            throws CredentialIssuanceException {

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(jwtString);
        } catch (Exception e) {
            throw new CredentialIssuanceException("Invalid JWT proof format", e);
        }

        // Validate header
        validateHeader(signedJWT);

        // Extract public key from header
        JWK publicKey = extractPublicKey(signedJWT);

        // Verify signature
        verifySignature(signedJWT, publicKey);

        // Validate claims
        validateClaims(signedJWT, issuerIdentifier, tenantDomain);

        // Build and return ProofDTO
        ProofDTO proofDTO = new ProofDTO();
        proofDTO.setProofType(PROOF_TYPE_JWT);
        proofDTO.setPublicKey(publicKey.toJSONObject());

        try {
            if (signedJWT.getJWTClaimsSet().getIssueTime() != null) {
                proofDTO.setIssuedAt(
                        signedJWT.getJWTClaimsSet().getIssueTime().getTime());
            }
            Object nonce = signedJWT.getJWTClaimsSet().getClaim("nonce");
            if (nonce != null) {
                proofDTO.setNonce(nonce.toString());
            }
        } catch (Exception e) {
            LOG.warn("Error extracting claims from proof JWT", e);
        }

        return proofDTO;
    }

    private void validateHeader(SignedJWT signedJWT)
            throws CredentialIssuanceException {

        // Check typ header
        if (signedJWT.getHeader().getType() == null) {
            throw new CredentialIssuanceException("Missing typ header in proof JWT");
        }

        String typ = signedJWT.getHeader().getType().toString();
        if (!EXPECTED_TYP.equals(typ)) {
            throw new CredentialIssuanceException(
                    "Invalid typ header. Expected: " + EXPECTED_TYP + ", got: " + typ);
        }

        // Check algorithm is not 'none'
        String alg = signedJWT.getHeader().getAlgorithm().getName();
        if ("none".equalsIgnoreCase(alg)) {
            throw new CredentialIssuanceException("Algorithm 'none' is not allowed");
        }
    }

    private JWK extractPublicKey(SignedJWT signedJWT)
            throws CredentialIssuanceException {

        try {
            JWK jwk = signedJWT.getHeader().getJWK();
            if (jwk == null) {
                throw new CredentialIssuanceException(
                        "Public key (jwk) must be present in proof header");
            }
            return jwk;
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Failed to extract public key", e);
        }
    }

    private void verifySignature(SignedJWT signedJWT, JWK publicKey)
            throws CredentialIssuanceException {

        try {
            JWSVerifier verifier;
            String keyType = publicKey.getKeyType().getValue();

            if ("EC".equals(keyType)) {
                ECKey ecKey = ECKey.parse(publicKey.toJSONObject());
                verifier = new ECDSAVerifier(ecKey);
            } else if ("RSA".equals(keyType)) {
                RSAKey rsaKey = RSAKey.parse(publicKey.toJSONObject());
                verifier = new RSASSAVerifier(rsaKey);
            } else {
                throw new CredentialIssuanceException(
                        "Unsupported key type: " + keyType);
            }

            if (!signedJWT.verify(verifier)) {
                throw new CredentialIssuanceException(
                        "Proof signature verification failed");
            }
        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Signature verification failed", e);
        }
    }

    private void validateClaims(SignedJWT signedJWT,
            String issuerIdentifier,
            String tenantDomain)
            throws CredentialIssuanceException {

        try {
            // Validate aud
            List<String> audience = signedJWT.getJWTClaimsSet().getAudience();
            if (audience == null || audience.isEmpty()) {
                throw new CredentialIssuanceException("Missing aud claim in proof");
            }

            String aud = audience.get(0);
            if (!issuerIdentifier.equals(aud)) {
                throw new CredentialIssuanceException(
                        "Invalid aud claim. Expected: " + issuerIdentifier
                                + ", got: " + aud);
            }

            // Validate iat
            if (signedJWT.getJWTClaimsSet().getIssueTime() == null) {
                throw new CredentialIssuanceException("Missing iat claim in proof");
            }

            long iat = signedJWT.getJWTClaimsSet().getIssueTime().getTime() / 1000;
            long now = System.currentTimeMillis() / 1000;
            if (Math.abs(now - iat) > MAX_CLOCK_SKEW_SECONDS) {
                throw new CredentialIssuanceException(
                        "Proof is too old or from the future");
            }

            // Validate nonce if present
            Object nonceObj = signedJWT.getJWTClaimsSet().getClaim("nonce");
            if (nonceObj != null) {
                String nonce = nonceObj.toString();
                if (!nonceManager.validateAndConsumeNonce(nonce, tenantDomain)) {
                    throw new CredentialIssuanceException(
                            "Invalid or expired nonce");
                }
            }

        } catch (CredentialIssuanceException e) {
            throw e;
        } catch (Exception e) {
            throw new CredentialIssuanceException("Claim validation failed", e);
        }
    }
}
