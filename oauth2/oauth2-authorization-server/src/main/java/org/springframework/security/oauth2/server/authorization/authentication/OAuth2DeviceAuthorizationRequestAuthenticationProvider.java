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

import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.BytesKeyGenerator;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * An {@link AuthenticationProvider} implementation for the Device Authorization Request
 * used in the OAuth 2.0 Device Authorization Grant.
 *
 * @author Steve Riesenberg
 * @since 7.0
 * @see OAuth2DeviceAuthorizationRequestAuthenticationToken
 * @see OAuth2DeviceVerificationAuthenticationProvider
 * @see OAuth2DeviceAuthorizationConsentAuthenticationProvider
 * @see OAuth2DeviceCodeAuthenticationProvider
 * @see OAuth2AuthorizationService
 * @see OAuth2TokenGenerator
 * @see <a target="_blank" href="https://datatracker.ietf.org/doc/html/rfc8628">OAuth 2.0
 * Device Authorization Grant</a>
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc8628#section-3.1">Section 3.1 Device
 * Authorization Request</a>
 */
public final class OAuth2DeviceAuthorizationRequestAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	static final OAuth2TokenType DEVICE_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.DEVICE_CODE);
	static final OAuth2TokenType USER_CODE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.USER_CODE);

	private final Log logger = LogFactory.getLog(getClass());

	private final OAuth2AuthorizationService authorizationService;

	private OAuth2TokenGenerator<OAuth2DeviceCode> deviceCodeGenerator = new OAuth2DeviceCodeGenerator();

	private OAuth2TokenGenerator<OAuth2UserCode> userCodeGenerator = new OAuth2UserCodeGenerator();

	/**
	 * Constructs an {@code OAuth2DeviceAuthorizationRequestAuthenticationProvider} using
	 * the provided parameters.
	 * @param authorizationService the authorization service
	 */
	public OAuth2DeviceAuthorizationRequestAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2DeviceAuthorizationRequestAuthenticationToken deviceAuthorizationRequestAuthentication = (OAuth2DeviceAuthorizationRequestAuthenticationToken) authentication;

		OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
			.getAuthenticatedClientElseThrowInvalidClient(deviceAuthorizationRequestAuthentication);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Retrieved registered client");
		}

		if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.DEVICE_CODE)) {
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format(
						"Invalid request: requested grant_type is not allowed" + " for registered client '%s'",
						registeredClient.getId()));
			}
			throwError(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, OAuth2ParameterNames.CLIENT_ID);
		}

		Set<String> requestedScopes = deviceAuthorizationRequestAuthentication.getScopes();
		if (!CollectionUtils.isEmpty(requestedScopes)) {
			for (String requestedScope : requestedScopes) {
				if (!registeredClient.getScopes().contains(requestedScope)) {
					throwError(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ParameterNames.SCOPE);
				}
			}
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Validated device authorization request parameters");
		}

		// @formatter:off
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.authorizationGrant(deviceAuthorizationRequestAuthentication);
		// @formatter:on

		// Generate a high-entropy string to use as the device code
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(DEVICE_CODE_TOKEN_TYPE).build();
		OAuth2DeviceCode deviceCode = this.deviceCodeGenerator.generate(tokenContext);
		if (deviceCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the device code.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated device code");
		}

		// Generate a low-entropy string to use as the user code
		tokenContext = tokenContextBuilder.tokenType(USER_CODE_TOKEN_TYPE).build();
		OAuth2UserCode userCode = this.userCodeGenerator.generate(tokenContext);
		if (userCode == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the user code.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Generated user code");
		}

		// @formatter:off
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
				.token(deviceCode)
				.token(userCode)
				.attribute(OAuth2ParameterNames.SCOPE, new HashSet<>(requestedScopes))
				.build();
		// @formatter:on
		this.authorizationService.save(authorization);

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Saved authorization");
		}

		if (this.logger.isTraceEnabled()) {
			this.logger.trace("Authenticated device authorization request");
		}

		return new OAuth2DeviceAuthorizationRequestAuthenticationToken(clientPrincipal, requestedScopes, deviceCode,
				userCode);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2DeviceAuthorizationRequestAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the {@link OAuth2DeviceCode}.
	 * @param deviceCodeGenerator the {@link OAuth2TokenGenerator} that generates the
	 * {@link OAuth2DeviceCode}
	 */
	public void setDeviceCodeGenerator(OAuth2TokenGenerator<OAuth2DeviceCode> deviceCodeGenerator) {
		Assert.notNull(deviceCodeGenerator, "deviceCodeGenerator cannot be null");
		this.deviceCodeGenerator = deviceCodeGenerator;
	}

	/**
	 * Sets the {@link OAuth2TokenGenerator} that generates the {@link OAuth2UserCode}.
	 * @param userCodeGenerator the {@link OAuth2TokenGenerator} that generates the
	 * {@link OAuth2UserCode}
	 */
	public void setUserCodeGenerator(OAuth2TokenGenerator<OAuth2UserCode> userCodeGenerator) {
		Assert.notNull(userCodeGenerator, "userCodeGenerator cannot be null");
		this.userCodeGenerator = userCodeGenerator;
	}

	private static void throwError(String errorCode, String parameterName) {
		OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

	private static final class OAuth2DeviceCodeGenerator implements OAuth2TokenGenerator<OAuth2DeviceCode> {

		private final StringKeyGenerator deviceCodeGenerator = new Base64StringKeyGenerator(
				Base64.getUrlEncoder().withoutPadding(), 96);

		@Nullable
		@Override
		public OAuth2DeviceCode generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null
					|| !OAuth2ParameterNames.DEVICE_CODE.equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt
				.plus(context.getRegisteredClient().getTokenSettings().getDeviceCodeTimeToLive());
			return new OAuth2DeviceCode(this.deviceCodeGenerator.generateKey(), issuedAt, expiresAt);
		}

	}

	private static final class UserCodeStringKeyGenerator implements StringKeyGenerator {

		// @formatter:off
		private static final char[] VALID_CHARS = {
				'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M',
				'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W', 'X', 'Z'
		};
		// @formatter:on

		private final BytesKeyGenerator keyGenerator = KeyGenerators.secureRandom(8);

		@Override
		public String generateKey() {
			byte[] bytes = this.keyGenerator.generateKey();
			StringBuilder sb = new StringBuilder();
			for (byte b : bytes) {
				int offset = Math.abs(b % 20);
				sb.append(VALID_CHARS[offset]);
			}
			sb.insert(4, '-');
			return sb.toString();
		}

	}

	private static final class OAuth2UserCodeGenerator implements OAuth2TokenGenerator<OAuth2UserCode> {

		private final StringKeyGenerator userCodeGenerator = new UserCodeStringKeyGenerator();

		@Nullable
		@Override
		public OAuth2UserCode generate(OAuth2TokenContext context) {
			if (context.getTokenType() == null
					|| !OAuth2ParameterNames.USER_CODE.equals(context.getTokenType().getValue())) {
				return null;
			}
			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt
				.plus(context.getRegisteredClient().getTokenSettings().getDeviceCodeTimeToLive());
			return new OAuth2UserCode(this.userCodeGenerator.generateKey(), issuedAt, expiresAt);
		}

	}

}
