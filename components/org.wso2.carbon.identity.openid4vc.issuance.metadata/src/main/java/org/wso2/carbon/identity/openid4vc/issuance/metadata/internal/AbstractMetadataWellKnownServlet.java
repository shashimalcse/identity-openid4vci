/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vc.issuance.metadata.internal;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.openid4vc.issuance.common.constant.Constants;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.DefaultCredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vc.issuance.metadata.response.CredentialIssuerMetadataResponse;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Base servlet for the credential issuer well-known metadata documents, which OpenID4VCI 1.0
 * section 12.2.2 places at the root context rather than inside the {@code /oid4vci} web
 * application. Handles {@code /{context}} and {@code /t/{tenant}/{context}}.
 */
abstract class AbstractMetadataWellKnownServlet extends HttpServlet {

    private static final long serialVersionUID = -3162745900274638927L;
    private static final Log LOG = LogFactory.getLog(AbstractMetadataWellKnownServlet.class);

    private static final Pattern ALLOWED_PATH_PATTERN =
            Pattern.compile("^/(?:t/([^/]+)/)?" + Constants.CONTEXT_OPENID4VCI + "$");
    private static final String CONTENT_TYPE_JSON = "application/json";
    private static final String CHARACTER_ENCODING = "UTF-8";
    private static final String SERVER_ERROR_RESPONSE =
            "{\"error\":\"server_error\",\"error_description\":\"Error while resolving %s.\"}";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {

        Matcher matcher = ALLOWED_PATH_PATTERN.matcher(StringUtils.defaultString(request.getPathInfo()));
        if (!matcher.matches()) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        String tenantDomain = matcher.group(1);
        if (StringUtils.isBlank(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }

        response.setContentType(CONTENT_TYPE_JSON);
        response.setCharacterEncoding(CHARACTER_ENCODING);
        try {
            CredentialIssuerMetadataResponse metadataResponse =
                    resolveMetadata(getCredentialIssuerMetadataProcessor(), tenantDomain);
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().print(metadataResponse.toJson());
        } catch (CredentialIssuerMetadataException e) {
            LOG.error(String.format("Error while resolving %s for tenant: %s", getMetadataTypeName(), tenantDomain), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().print(String.format(SERVER_ERROR_RESPONSE, getMetadataTypeName()));
        }
    }

    /**
     * Resolve the metadata document served by this servlet.
     *
     * @param processor    Metadata processor to resolve the document from.
     * @param tenantDomain Tenant domain resolving the credential issuer.
     * @return Metadata response payload.
     * @throws CredentialIssuerMetadataException On metadata retrieval failures.
     */
    protected abstract CredentialIssuerMetadataResponse resolveMetadata(
            CredentialIssuerMetadataProcessor processor, String tenantDomain)
            throws CredentialIssuerMetadataException;

    /**
     * @return Name of the metadata document, used in log and error messages.
     */
    protected abstract String getMetadataTypeName();

    protected CredentialIssuerMetadataProcessor getCredentialIssuerMetadataProcessor() {

        return DefaultCredentialIssuerMetadataProcessor.getInstance();
    }
}
