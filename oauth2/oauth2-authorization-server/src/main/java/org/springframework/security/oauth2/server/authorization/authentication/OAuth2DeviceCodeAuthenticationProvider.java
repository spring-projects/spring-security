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

import java.security.Principal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation for the Device Access Token Request
 * used in the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 1.1
 * @see OAuth2DeviceCodeAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see OAuth2DeviceAuthorizationRequestAuthenticationProvider
 * @see OAuth2DeviceVerificationAuthenticationProvider
 * @see OAuth2DeviceAuthorizationConsentAuthenticationProvider
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0
 * Device Authorization Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8628#section-3.4">Section 3.4 Device Access
 * Token Request</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5">Section 3.5 Device Access
 * Token Response</a>
 */
public final class OAuth2DeviceCodeAuthenticationProvider implements AuthenticationProvider {

	private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final String DEVICE_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc8628#section-3.5";
	static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);
	static final String EXPIRED_TOKEN = "expired_token";
	static final String AUTHORIZATION_PENDING = "authorization_pending";

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	/**
	 * Constructs an {@code OAuth2DeviceCodeAuthenticationProvider} using the provided
	 * parameters.
	 * @param authorizationService the authorization service
	 * @param tokenGenerator the token generator
	 */
	public OAuth2DeviceCodeAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2DeviceCodeAuthenticationToken deviceCodeAuthentication = (OAuth2DeviceCodeAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(deviceCodeAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		OAuth2Authorization authorization = this.authorizationService
			.findByToken(deviceCodeAuthentication.getDeviceCode(), DEVICE_CODE_TOKEN_TYPE);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved authorization with device code");
		}

		OAuth2Authorization.Token<OAuth2UserCode> userCode = authorization.getToken(OAuth2UserCode.class);
		OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode = authorization.getToken(OAuth2DeviceCode.class);

		if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
			if (!deviceCode.isInvalidated()) {
				// Invalidate the device code given that a different client is attempting
				// to use it
				authorization = OAuth2Authorization.from(authorization).invalidate(deviceCode.getToken()).build();
				this.authorizationService.save(authorization);
				if (this.logger.isWarnEnabled()) {
					this.logger.warn(LogMessage.format("Invalidated device code used by registered client '%s'",
							authorization.getRegisteredClientId()));
				}
			}
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
		}

		// In https://www.rfc-editor.org/rfc/rfc8628.html#section-3.5,
		// the following error codes are defined:

		// expired_token
		// The "device_code" has expired, and the device authorization
		// session has concluded. The client MAY commence a new device
		// authorization request but SHOULD wait for user interaction before
		// restarting to avoid unnecessary polling.
		if (deviceCode.isExpired()) {
			if (!deviceCode.isInvalidated()) {
				// Invalidate the device code
				authorization = OAuth2Authorization.from(authorization).invalidate(deviceCode.getToken()).build();
				this.authorizationService.save(authorization);
				if (this.logger.isWarnEnabled()) {
					this.logger.warn(LogMessage.format("Invalidated device code used by registered client '%s'",
							authorization.getRegisteredClientId()));
				}
			}
			OAuth2Error error = new OAuth2Error(EXPIRED_TOKEN, null, DEVICE_ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		// authorization_pending
		// The authorization request is still pending as the end user hasn't
		// yet completed the user-interaction steps (Section 3.3). The
		// client SHOULD repeat the access token request to the token
		// endpoint (a process known as polling). Before each new request,
		// the client MUST wait at least the number of seconds specified by
		// the "interval" parameter of the device authorization response (see
		// Section 3.2), or 5 seconds if none was provided, and respect any
		// increase in the polling interval required by the "slow_down"
		// error.
		if (!userCode.isInvalidated()) {
			OAuth2Error error = new OAuth2Error(AUTHORIZATION_PENDING, null, DEVICE_ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		// slow_down
		// A variant of "authorization_pending", the authorization request is
		// still pending and polling should continue, but the interval MUST
		// be increased by 5 seconds for this and all subsequent requests.
		// NOTE: This error is not handled in the framework.

		// access_denied
		// The authorization request was denied.
		if (deviceCode.isInvalidated()) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED, null, DEVICE_ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		// Verify the DPoP Proof (if available)
		Jwt dPoPProof = DPoPProofVerifier.verifyIfAvailable(deviceCodeAuthentication);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated device token request parameters");
		}

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(authorization.getAttribute(Principal.class.getName()))
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorization(authorization)
				.authorizedScopes(authorization.getAuthorizedScopes())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrant(deviceCodeAuthentication);
		// @formatter:on
		if (dPoPProof != null) {
			tokenContextBuilder.put(OAuth2TokenContext.DPOP_PROOF_KEY, dPoPProof);
		}

		// @formatter:off
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
				// Invalidate the device code as it can only be used (successfully) once
				.invalidate(deviceCode.getToken());
		// @formatter:on

		// ----- Access token -----
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", DEFAULT_ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated access token");
		}

		OAuth2AccessToken accessToken = OAuth2AuthenticationProviderUtils.accessToken(authorizationBuilder,
				generatedAccessToken, tokenContext);

		// ----- Refresh token -----
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", DEFAULT_ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (this.logger.isTraceEnabled()) {
				this.logger.trace("Generated refresh token");
			}

			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}

		authorization = authorizationBuilder.build();

		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated device token request");
		}

		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceCodeAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
