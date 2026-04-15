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

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;
import java.util.function.Consumer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.util.CollectionUtils;

/**
 * A {@code Consumer} providing access to the
 * {@link OAuth2ClientRegistrationAuthenticationContext} containing an
 * {@link OAuth2ClientRegistrationAuthenticationToken} and is the default
 * {@link OAuth2ClientRegistrationAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OAuth 2.0 Dynamic Client
 * Registration Request parameters (RFC 7591).
 *
 * <p>
 * The default implementation validates
 * {@link OAuth2ClientRegistration#getRedirectUris() redirect_uris},
 * {@link OAuth2ClientRegistration#getJwkSetUrl() jwks_uri}, and
 * {@link OAuth2ClientRegistration#getScopes() scope}. If validation fails, an
 * {@link OAuth2AuthenticationException} is thrown.
 *
 * <p>
 * Each validated field is backed by two public constants:
 * <ul>
 * <li>{@code DEFAULT_*_VALIDATOR} — strict validation that rejects unsafe values. This is
 * the default behavior and may reject input that was previously accepted.</li>
 * <li>{@code SIMPLE_*_VALIDATOR} — lenient validation preserving the behavior from prior
 * releases. Use only when strictly required for backward compatibility and with full
 * understanding that it may accept values that enable attacks against the authorization
 * server.</li>
 * </ul>
 *
 * @author addcontent
 * @since 7.0
 * @see OAuth2ClientRegistrationAuthenticationContext
 * @see OAuth2ClientRegistrationAuthenticationToken
 * @see OAuth2ClientRegistrationAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OAuth2ClientRegistrationAuthenticationValidator
		implements Consumer<OAuth2ClientRegistrationAuthenticationContext> {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2";

	private static final Log LOGGER = LogFactory.getLog(OAuth2ClientRegistrationAuthenticationValidator.class);

	/**
	 * The default validator for
	 * {@link OAuth2ClientRegistration#getRedirectUris() redirect_uris}. Rejects URIs that
	 * contain a fragment, have no scheme (e.g. protocol-relative {@code //host/path}), or
	 * use an unsafe scheme ({@code javascript}, {@code data}, {@code vbscript}).
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> DEFAULT_REDIRECT_URI_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateRedirectUris;

	/**
	 * The simple validator for
	 * {@link OAuth2ClientRegistration#getRedirectUris() redirect_uris} that preserves
	 * prior behavior (fragment-only check). Use only when backward compatibility is
	 * required; values that enable open redirect and XSS attacks may be accepted.
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> SIMPLE_REDIRECT_URI_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateRedirectUrisSimple;

	/**
	 * The default validator for {@link OAuth2ClientRegistration#getJwkSetUrl() jwks_uri}.
	 * Rejects URIs that do not use the {@code https} scheme.
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> DEFAULT_JWK_SET_URI_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateJwkSetUri;

	/**
	 * The simple validator for {@link OAuth2ClientRegistration#getJwkSetUrl() jwks_uri}
	 * that preserves prior behavior (no validation). Use only when backward compatibility
	 * is required; values that enable SSRF attacks may be accepted.
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> SIMPLE_JWK_SET_URI_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateJwkSetUriSimple;

	/**
	 * The default validator for {@link OAuth2ClientRegistration#getScopes() scope}.
	 * Rejects any request that includes a non-empty scope value. Deployers that need to
	 * accept scopes during Dynamic Client Registration must configure their own validator
	 * (for example by chaining on top of {@link #SIMPLE_SCOPE_VALIDATOR}).
	 *
	 * <p>
	 * <b>NOTE:</b> This default behavior is tentative and may be adjusted prior to
	 * release based on the final fix design.
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateScope;

	/**
	 * The simple validator for {@link OAuth2ClientRegistration#getScopes() scope} that
	 * preserves prior behavior (accepts any scope). Use only when backward compatibility
	 * is required; values that enable arbitrary scope injection may be accepted.
	 */
	public static final Consumer<OAuth2ClientRegistrationAuthenticationContext> SIMPLE_SCOPE_VALIDATOR = OAuth2ClientRegistrationAuthenticationValidator::validateScopeSimple;

	private final Consumer<OAuth2ClientRegistrationAuthenticationContext> authenticationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
		.andThen(DEFAULT_JWK_SET_URI_VALIDATOR)
		.andThen(DEFAULT_SCOPE_VALIDATOR);

	@Override
	public void accept(OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateRedirectUris(OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> redirectUris = clientRegistrationAuthentication.getClientRegistration().getRedirectUris();
		if (CollectionUtils.isEmpty(redirectUris)) {
			return;
		}
		for (String redirectUri : redirectUris) {
			URI parsed;
			try {
				parsed = new URI(redirectUri);
			}
			catch (URISyntaxException ex) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: redirect_uri is not parseable ('%s')", redirectUri));
				}
				throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
				return;
			}
			if (parsed.getFragment() != null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: redirect_uri contains a fragment ('%s')",
							redirectUri));
				}
				throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			}
			String scheme = parsed.getScheme();
			if (scheme == null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: redirect_uri has no scheme ('%s')", redirectUri));
				}
				throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			}
			if (isUnsafeScheme(scheme)) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: redirect_uri uses unsafe scheme ('%s')",
							redirectUri));
				}
				throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			}
		}
	}

	private static void validateRedirectUrisSimple(
			OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> redirectUris = clientRegistrationAuthentication.getClientRegistration().getRedirectUris();
		if (CollectionUtils.isEmpty(redirectUris)) {
			return;
		}
		for (String redirectUri : redirectUris) {
			try {
				URI parsed = new URI(redirectUri);
				if (parsed.getFragment() != null) {
					throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
							OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
				}
			}
			catch (URISyntaxException ex) {
				throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						OAuth2ClientMetadataClaimNames.REDIRECT_URIS);
			}
		}
	}

	private static void validateJwkSetUri(OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		URL jwkSetUrl = clientRegistrationAuthentication.getClientRegistration().getJwkSetUrl();
		if (jwkSetUrl == null) {
			return;
		}
		if (!"https".equalsIgnoreCase(jwkSetUrl.getProtocol())) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format("Invalid request: jwks_uri does not use https ('%s')", jwkSetUrl));
			}
			throwInvalidClientRegistration("invalid_client_metadata", OAuth2ClientMetadataClaimNames.JWKS_URI);
		}
	}

	private static void validateJwkSetUriSimple(
			OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		// No validation. Preserves prior behavior.
	}

	private static void validateScope(OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		OAuth2ClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> scopes = clientRegistrationAuthentication.getClientRegistration().getScopes();
		if (!CollectionUtils.isEmpty(scopes)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format(
						"Invalid request: scope must not be set during Dynamic Client Registration ('%s')", scopes));
			}
			throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_SCOPE, OAuth2ClientMetadataClaimNames.SCOPE);
		}
	}

	private static void validateScopeSimple(OAuth2ClientRegistrationAuthenticationContext authenticationContext) {
		// No validation. Preserves prior behavior.
	}

	private static boolean isUnsafeScheme(String scheme) {
		return "javascript".equalsIgnoreCase(scheme) || "data".equalsIgnoreCase(scheme)
				|| "vbscript".equalsIgnoreCase(scheme);
	}

	private static void throwInvalidClientRegistration(String errorCode, String fieldName) {
		OAuth2Error error = new OAuth2Error(errorCode, "Invalid Client Registration: " + fieldName, ERROR_URI);
		throw new OAuth2AuthenticationException(error);
	}

}
