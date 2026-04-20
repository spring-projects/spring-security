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

package org.springframework.security.oauth2.server.authorization.oidc.authentication;

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
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.util.CollectionUtils;

/**
 * A {@code Consumer} providing access to the
 * {@link OidcClientRegistrationAuthenticationContext} containing an
 * {@link OidcClientRegistrationAuthenticationToken} and is the default
 * {@link OidcClientRegistrationAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OpenID Connect 1.0 Dynamic
 * Client Registration Request parameters.
 *
 * <p>
 * The default implementation validates {@link OidcClientRegistration#getRedirectUris()
 * redirect_uris}, {@link OidcClientRegistration#getPostLogoutRedirectUris()
 * post_logout_redirect_uris}, {@link OidcClientRegistration#getJwkSetUrl() jwks_uri}, and
 * {@link OidcClientRegistration#getScopes() scope}. If validation fails, an
 * {@link OAuth2AuthenticationException} is thrown.
 *
 * <p>
 * Each validated field is backed by two public constants:
 * <ul>
 * <li>{@code DEFAULT_*_VALIDATOR} -- strict validation that rejects unsafe values. This is
 * the default behavior and may reject input that was previously accepted.</li>
 * <li>{@code SIMPLE_*_VALIDATOR} -- lenient validation preserving the behavior from prior
 * releases. Use only when strictly required for backward compatibility and with full
 * understanding that it may accept values that enable attacks against the authorization
 * server.</li>
 * </ul>
 *
 * @author addcontent
 * @since 7.0.5
 * @see OidcClientRegistrationAuthenticationContext
 * @see OidcClientRegistrationAuthenticationToken
 * @see OidcClientRegistrationAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OidcClientRegistrationAuthenticationValidator
		implements Consumer<OidcClientRegistrationAuthenticationContext> {

	private static final String ERROR_URI = "https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationError";

	private static final Log LOGGER = LogFactory.getLog(OidcClientRegistrationAuthenticationValidator.class);

	/**
	 * The default validator for {@link OidcClientRegistration#getRedirectUris()
	 * redirect_uris}. Rejects URIs that contain a fragment, have no scheme (e.g.
	 * protocol-relative {@code //host/path}), or use an unsafe scheme
	 * ({@code javascript}, {@code data}, {@code vbscript}).
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> DEFAULT_REDIRECT_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateRedirectUris;

	/**
	 * The simple validator for {@link OidcClientRegistration#getRedirectUris()
	 * redirect_uris} that preserves prior behavior (fragment-only check). Use only when
	 * backward compatibility is required; values that enable open redirect and XSS
	 * attacks may be accepted.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> SIMPLE_REDIRECT_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateRedirectUrisSimple;

	/**
	 * The default validator for {@link OidcClientRegistration#getPostLogoutRedirectUris()
	 * post_logout_redirect_uris}. Applies the same rules as
	 * {@link #DEFAULT_REDIRECT_URI_VALIDATOR}.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validatePostLogoutRedirectUris;

	/**
	 * The simple validator for {@link OidcClientRegistration#getPostLogoutRedirectUris()
	 * post_logout_redirect_uris} that preserves prior behavior (fragment-only check). Use
	 * only when backward compatibility is required; values that enable XSS attacks on the
	 * authorization server origin may be accepted.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> SIMPLE_POST_LOGOUT_REDIRECT_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validatePostLogoutRedirectUrisSimple;

	/**
	 * The default validator for {@link OidcClientRegistration#getJwkSetUrl() jwks_uri}.
	 * Rejects URIs that do not use the {@code https} scheme.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> DEFAULT_JWK_SET_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateJwkSetUri;

	/**
	 * The simple validator for {@link OidcClientRegistration#getJwkSetUrl() jwks_uri}
	 * that preserves prior behavior (no validation). Use only when backward compatibility
	 * is required; values that enable SSRF attacks may be accepted.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> SIMPLE_JWK_SET_URI_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateJwkSetUriSimple;

	/**
	 * The default validator for {@link OidcClientRegistration#getScopes() scope}. Rejects
	 * any request that includes a non-empty scope value. Deployers that need to accept
	 * scopes during Dynamic Client Registration must configure their own validator (for
	 * example, by chaining on top of {@link #SIMPLE_SCOPE_VALIDATOR}).
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> DEFAULT_SCOPE_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateScope;

	/**
	 * The simple validator for {@link OidcClientRegistration#getScopes() scope} that
	 * preserves prior behavior (accepts any scope). Use only when backward compatibility
	 * is required; values that enable arbitrary scope injection may be accepted.
	 */
	public static final Consumer<OidcClientRegistrationAuthenticationContext> SIMPLE_SCOPE_VALIDATOR = OidcClientRegistrationAuthenticationValidator::validateScopeSimple;

	private final Consumer<OidcClientRegistrationAuthenticationContext> authenticationValidator = DEFAULT_REDIRECT_URI_VALIDATOR
		.andThen(DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR)
		.andThen(DEFAULT_JWK_SET_URI_VALIDATOR)
		.andThen(DEFAULT_SCOPE_VALIDATOR);

	@Override
	public void accept(OidcClientRegistrationAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validateRedirectUris(OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> redirectUris = clientRegistrationAuthentication.getClientRegistration().getRedirectUris();
		validateRedirectUrisStrict(redirectUris, OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	private static void validatePostLogoutRedirectUris(
			OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> postLogoutRedirectUris = clientRegistrationAuthentication.getClientRegistration()
			.getPostLogoutRedirectUris();
		validateRedirectUrisStrict(postLogoutRedirectUris, "invalid_client_metadata",
				OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	private static void validateRedirectUrisStrict(List<String> redirectUris, String errorCode, String fieldName) {
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
					LOGGER.debug(
							LogMessage.format("Invalid request: %s is not parseable ('%s')", fieldName, redirectUri));
				}
				throwInvalidClientRegistration(errorCode, fieldName);
				return;
			}
			if (parsed.getFragment() != null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: %s contains a fragment ('%s')", fieldName,
							redirectUri));
				}
				throwInvalidClientRegistration(errorCode, fieldName);
			}
			String scheme = parsed.getScheme();
			if (scheme == null) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(LogMessage.format("Invalid request: %s has no scheme ('%s')", fieldName, redirectUri));
				}
				throwInvalidClientRegistration(errorCode, fieldName);
			}
			if (isUnsafeScheme(scheme)) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(
							LogMessage.format("Invalid request: %s uses unsafe scheme ('%s')", fieldName, redirectUri));
				}
				throwInvalidClientRegistration(errorCode, fieldName);
			}
		}
	}

	private static void validateRedirectUrisSimple(OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> redirectUris = clientRegistrationAuthentication.getClientRegistration().getRedirectUris();
		validateRedirectUrisFragmentOnly(redirectUris, OAuth2ErrorCodes.INVALID_REDIRECT_URI,
				OidcClientMetadataClaimNames.REDIRECT_URIS);
	}

	private static void validatePostLogoutRedirectUrisSimple(
			OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> postLogoutRedirectUris = clientRegistrationAuthentication.getClientRegistration()
			.getPostLogoutRedirectUris();
		validateRedirectUrisFragmentOnly(postLogoutRedirectUris, "invalid_client_metadata",
				OidcClientMetadataClaimNames.POST_LOGOUT_REDIRECT_URIS);
	}

	private static void validateRedirectUrisFragmentOnly(List<String> redirectUris, String errorCode,
			String fieldName) {
		if (CollectionUtils.isEmpty(redirectUris)) {
			return;
		}
		for (String redirectUri : redirectUris) {
			try {
				URI parsed = new URI(redirectUri);
				if (parsed.getFragment() != null) {
					throwInvalidClientRegistration(errorCode, fieldName);
				}
			}
			catch (URISyntaxException ex) {
				throwInvalidClientRegistration(errorCode, fieldName);
			}
		}
	}

	private static void validateJwkSetUri(OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		URL jwkSetUrl = clientRegistrationAuthentication.getClientRegistration().getJwkSetUrl();
		if (jwkSetUrl == null) {
			return;
		}
		if (!"https".equalsIgnoreCase(jwkSetUrl.getProtocol())) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format("Invalid request: jwks_uri does not use https ('%s')", jwkSetUrl));
			}
			throwInvalidClientRegistration("invalid_client_metadata", OidcClientMetadataClaimNames.JWKS_URI);
		}
	}

	private static void validateJwkSetUriSimple(OidcClientRegistrationAuthenticationContext authenticationContext) {
		// No validation. Preserves prior behavior.
	}

	private static void validateScope(OidcClientRegistrationAuthenticationContext authenticationContext) {
		OidcClientRegistrationAuthenticationToken clientRegistrationAuthentication = authenticationContext
			.getAuthentication();
		List<String> scopes = clientRegistrationAuthentication.getClientRegistration().getScopes();
		if (!CollectionUtils.isEmpty(scopes)) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug(LogMessage.format(
						"Invalid request: scope must not be set during Dynamic Client Registration ('%s')", scopes));
			}
			throwInvalidClientRegistration(OAuth2ErrorCodes.INVALID_SCOPE, OidcClientMetadataClaimNames.SCOPE);
		}
	}

	private static void validateScopeSimple(OidcClientRegistrationAuthenticationContext authenticationContext) {
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
