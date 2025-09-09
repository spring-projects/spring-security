/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.server.authorization.authentication;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An authenticator used for OAuth 2.0 Client Authentication, which authenticates the
 * {@link PkceParameterNames#CODE_VERIFIER code_verifier} parameter.
 *
 * @author Daniel Garnier-Moiroux
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2AuthorizationService
 */
final class CodeVerifierAuthenticator {

	private static final OAuth2TokenType AUTHORIZATION_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.CODE);

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	CodeVerifierAuthenticator(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	void authenticateRequired(OAuth2ClientAuthenticationToken clientAuthentication, RegisteredClient registeredClient) {
		if (!authenticate(clientAuthentication, registeredClient)) {
			throwInvalidGrant(PkceParameterNames.CODE_VERIFIER);
		}
	}

	void authenticateIfAvailable(OAuth2ClientAuthenticationToken clientAuthentication,
			RegisteredClient registeredClient) {
		authenticate(clientAuthentication, registeredClient);
	}

	private boolean authenticate(OAuth2ClientAuthenticationToken clientAuthentication,
			RegisteredClient registeredClient) {

		Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
		if (!authorizationCodeGrant(parameters)) {
			return false;
		}

		OAuth2Authorization authorization = this.authorizationService
			.findByToken((String) parameters.get(OAuth2ParameterNames.CODE), AUTHORIZATION_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throwInvalidGrant(OAuth2ParameterNames.CODE);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with authorization code");
		}

		OAuth2AuthorizationRequest authorizationRequest = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());

		String codeChallenge = (String) authorizationRequest.getAdditionalParameters()
			.get(PkceParameterNames.CODE_CHALLENGE);
		String codeVerifier = (String) parameters.get(PkceParameterNames.CODE_VERIFIER);
		if (!StringUtils.hasText(codeChallenge)) {
			if (registeredClient.getClientSettings().isRequireProofKey() || StringUtils.hasText(codeVerifier)) {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(LogMessage.format(
							"Invalid request: code_challenge is required" + " for registered client '%s'",
							registeredClient.getId()));
				}
				throwInvalidGrant(PkceParameterNames.CODE_CHALLENGE);
			}
			else {
				if (this.logger.isTraceEnabled()) {
					this.logger.trace("Did not authenticate code verifier since requireProofKey=false");
				}
				return false;
			}
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated code verifier parameters");
		}

		String codeChallengeMethod = (String) authorizationRequest.getAdditionalParameters()
			.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
		if (!codeVerifierValid(codeVerifier, codeChallenge, codeChallengeMethod)) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: code_verifier is missing or invalid" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throwInvalidGrant(PkceParameterNames.CODE_VERIFIER);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated code verifier");
		}

		return true;
	}

	private static boolean authorizationCodeGrant(Map<String, Object> parameters) {
		if (!AuthorizationGrantType.AUTHORIZATION_CODE.getValue()
			.equals(parameters.get(OAuth2ParameterNames.GRANT_TYPE))) {
			return false;
		}
		if (!StringUtils.hasText((String) parameters.get(OAuth2ParameterNames.CODE))) {
			throwInvalidGrant(OAuth2ParameterNames.CODE);
		}
		return true;
	}

	private boolean codeVerifierValid(String codeVerifier, String codeChallenge, String codeChallengeMethod) {
		if (!StringUtils.hasText(codeVerifier)) {
			return false;
		}
		else if ("S256".equals(codeChallengeMethod)) {
			try {
				MessageDigest md = MessageDigest.getInstance("SHA-256");
				byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
				String encodedVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
				return encodedVerifier.equals(codeChallenge);
			}
			catch (NoSuchAlgorithmException ex) {
				// It is unlikely that SHA-256 is not available on the server. If it is
				// not available,
				// there will likely be bigger issues as well. We default to SERVER_ERROR.
				throw new OAuth2AuthenticationException(OAuth2ErrorCodes.SERVER_ERROR);
			}
		}
		return false;
	}

	private static void throwInvalidGrant(String parameterName) {
		OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT,
				"Client authentication failed: " + parameterName, null);
		throw new OAuth2AuthenticationException(error);
	}

}
