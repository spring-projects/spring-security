/*
 * Copyright 2020-2025 the original author or authors.
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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2AuthorizationCodeRequestAuthenticationContext} containing an
 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken} and is the default
 * {@link OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0 Authorization Request
 * parameters used in the Authorization Code Grant.
 *
 * <p>
 * The default implementation first validates
 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getRedirectUri()} and then
 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getScopes()}. If validation
 * fails, an {@link OAuth2AuthorizationCodeRequestAuthenticationException} is thrown.
 *
 * @author Joe Grandja
 * @since 0.4.0
 * @see OAuth2AuthorizationCodeRequestAuthenticationContext
 * @see OAuth2AuthorizationCodeRequestAuthenticationToken
 * @see OAuth2AuthorizationCodeRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 * @see OAuth2PushedAuthorizationRequestAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2AuthorizationCodeRequestAuthenticationValidator
		implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1";

	private static final String PKCE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7636#section-4.4.1";

	private static final Log LOGGER = LogFactory.getLog(OAuth2AuthorizationCodeRequestAuthenticationValidator.class);

	static final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> DEFAULT_AUTHORIZATION_GRANT_TYPE_VALIDATOR = OAuth2AuthorizationCodeRequestAuthenticationValidator::validateAuthorizationGrantType;

	static final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> DEFAULT_CODE_CHALLENGE_VALIDATOR = OAuth2AuthorizationCodeRequestAuthenticationValidator::validateCodeChallenge;

	static final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> DEFAULT_PROMPT_VALIDATOR = OAuth2AuthorizationCodeRequestAuthenticationValidator::validatePrompt;

	/**
	 * The default validator for
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getRedirectUri()}.
	 */
	public static final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> DEFAULT_REDIRECT_URI_VALIDATOR = OAuth2AuthorizationCodeRequestAuthenticationValidator::validateRedirectUri;

	/**
	 * The default validator for
	 * {@link OAuth2AuthorizationCodeRequestAuthenticationToken#getScopes()}.
	 */
	public static final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2AuthorizationCodeRequestAuthenticationValidator::validateScope;

	private final Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> authenticationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
		.andThen(DEFAULT_SCOPE_VALIDATOR);

	@Override
	public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateAuthorizationGrantType(
			OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
			.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format(
						"Invalid request: requested grant_type is not allowed for registered client '%s'",
						registeredClient.getId()));
			}
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID,
					authorizationCodeRequestAuthentication, registeredClient);
		}
	}

	private static void validateRedirectUri(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
			.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		String requestedRedirectUri = authorizationCodeRequestAuthentication.getRedirectUri();

		if (StringUtils.hasText(requestedRedirectUri)) {
			// ***** redirect_uri is available in authorization request

			UriComponents requestedRedirect = null;
			try {
				requestedRedirect = UriComponentsBuilder.fromUriString(requestedRedirectUri).build();
			}
			catch (Exception ex) {
			}
			if (requestedRedirect == null || requestedRedirect.getFragment() != null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: redirect_uri is missing or contains a fragment"
							+ " for registered client '%s'", registeredClient.getId()));
				}
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						authorizationCodeRequestAuthentication, registeredClient);
			}

			if (!isLoopbackAddress(requestedRedirect.getHost())) {
				// As per
				// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-22#section-4.1.3
				// When comparing client redirect URIs against pre-registered URIs,
				// authorization servers MUST utilize exact string matching.
				if (!registeredClient.getRedirectUris().contains(requestedRedirectUri)) {
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient);
				}
			}
			else {
				// As per
				// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-08#section-8.4.2
				// The authorization server MUST allow any port to be specified at the
				// time of the request for loopback IP redirect URIs, to accommodate
				// clients that obtain an available ephemeral port from the operating
				// system at the time of the request.
				boolean validRedirectUri = false;
				for (String registeredRedirectUri : registeredClient.getRedirectUris()) {
					UriComponentsBuilder registeredRedirect = UriComponentsBuilder.fromUriString(registeredRedirectUri);
					registeredRedirect.port(requestedRedirect.getPort());
					if (registeredRedirect.build().toString().equals(requestedRedirect.toString())) {
						validRedirectUri = true;
						break;
					}
				}
				if (!validRedirectUri) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug(LogMessage.format(
								"Invalid request: redirect_uri does not match for registered client '%s'",
								registeredClient.getId()));
					}
					throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
							authorizationCodeRequestAuthentication, registeredClient);
				}
			}

		}
		else {
			// ***** redirect_uri is NOT available in authorization request

			if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)
					|| registeredClient.getRedirectUris().size() != 1) {
				// redirect_uri is REQUIRED for OpenID Connect
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.REDIRECT_URI,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}
	}

	private static void validateScope(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
			.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		Set<String> requestedScopes = authorizationCodeRequestAuthentication.getScopes();
		Set<String> allowedScopes = registeredClient.getScopes();
		if (!requestedScopes.isEmpty() && !allowedScopes.containsAll(requestedScopes)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(
						LogMessage.format("Invalid request: requested scope is not allowed for registered client '%s'",
								registeredClient.getId()));
			}
			throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE,
					authorizationCodeRequestAuthentication, registeredClient);
		}
	}

	private static void validateCodeChallenge(
			OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
			.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		// code_challenge (REQUIRED for public clients) - RFC 7636 (PKCE)
		String codeChallenge = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
			.get(PkceParameterNames.CODE_CHALLENGE);
		if (StringUtils.hasText(codeChallenge)) {
			String codeChallengeMethod = (String) authorizationCodeRequestAuthentication.getAdditionalParameters()
				.get(PkceParameterNames.CODE_CHALLENGE_METHOD);
			if (!StringUtils.hasText(codeChallengeMethod) || !"S256".equals(codeChallengeMethod)) {
				throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE_METHOD, PKCE_ERROR_URI,
						authorizationCodeRequestAuthentication, registeredClient);
			}
		}
		else if (registeredClient.getClientSettings().isRequireProofKey()) {
			throwError(OAuth2ErrorCodes.INVALID_REQUEST, PkceParameterNames.CODE_CHALLENGE, PKCE_ERROR_URI,
					authorizationCodeRequestAuthentication, registeredClient);
		}
	}

	private static void validatePrompt(OAuth2AuthorizationCodeRequestAuthenticationContext authenticationContext) {
		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication = authenticationContext
			.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();

		// prompt (OPTIONAL for OpenID Connect 1.0 Authentication Request)
		if (authorizationCodeRequestAuthentication.getScopes().contains(OidcScopes.OPENID)) {
			String prompt = (String) authorizationCodeRequestAuthentication.getAdditionalParameters().get("prompt");
			if (StringUtils.hasText(prompt)) {
				Set<String> promptValues = new HashSet<>(
						Arrays.asList(StringUtils.delimitedListToStringArray(prompt, " ")));
				if (promptValues.contains(OidcPrompt.NONE)) {
					if (promptValues.contains(OidcPrompt.LOGIN) || promptValues.contains(OidcPrompt.CONSENT)
							|| promptValues.contains(OidcPrompt.SELECT_ACCOUNT)) {
						throwError(OAuth2ErrorCodes.INVALID_REQUEST, "prompt", authorizationCodeRequestAuthentication,
								registeredClient);
					}
				}
			}
		}
	}

	private static boolean isLoopbackAddress(String host) {
		if (!StringUtils.hasText(host)) {
			return false;
		}
		// IPv6 loopback address should either be "0:0:0:0:0:0:0:1" or "::1"
		if ("[0:0:0:0:0:0:0:1]".equals(host) || "[::1]".equals(host)) {
			return true;
		}
		// IPv4 loopback address ranges from 127.0.0.1 to 127.255.255.255
		String[] ipv4Octets = host.split("\\.");
		if (ipv4Octets.length != 4) {
			return false;
		}
		try {
			int[] address = new int[ipv4Octets.length];
			for (int i = 0; i < ipv4Octets.length; i++) {
				address[i] = Integer.parseInt(ipv4Octets[i]);
			}
			return address[0] == 127 && address[1] >= 0 && address[1] <= 255 && address[2] >= 0 && address[2] <= 255
					&& address[3] >= 1 && address[3] <= 255;
		}
		catch (NumberFormatException ex) {
			return false;
		}
	}

	private static void throwError(String errorCode, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		throwError(errorCode, parameterName, ERROR_URI, authorizationCodeRequestAuthentication, registeredClient);
	}

	private static void throwError(String errorCode, String parameterName, String errorUri,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, errorUri);
		throwError(error, parameterName, authorizationCodeRequestAuthentication, registeredClient);
	}

	private static void throwError(OAuth2Error error, String parameterName,
			OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthentication,
			RegisteredClient registeredClient) {

		String redirectUri = StringUtils.hasText(authorizationCodeRequestAuthentication.getRedirectUri())
				? authorizationCodeRequestAuthentication.getRedirectUri()
				: registeredClient.getRedirectUris().iterator().next();
		if (error.getErrorCode().equals(OAuth2ErrorCodes.INVALID_REQUEST)
				&& parameterName.equals(OAuth2ParameterNames.REDIRECT_URI)) {
			redirectUri = null; // Prevent redirects
		}

		OAuth2AuthorizationCodeRequestAuthenticationToken authorizationCodeRequestAuthenticationResult = new OAuth2AuthorizationCodeRequestAuthenticationToken(
				authorizationCodeRequestAuthentication.getAuthorizationUri(),
				authorizationCodeRequestAuthentication.getClientId(),
				(Authentication) authorizationCodeRequestAuthentication.getPrincipal(), redirectUri,
				authorizationCodeRequestAuthentication.getState(), authorizationCodeRequestAuthentication.getScopes(),
				authorizationCodeRequestAuthentication.getAdditionalParameters());
		authorizationCodeRequestAuthenticationResult.setAuthenticated(true);

		throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,
				authorizationCodeRequestAuthenticationResult);
	}

}
