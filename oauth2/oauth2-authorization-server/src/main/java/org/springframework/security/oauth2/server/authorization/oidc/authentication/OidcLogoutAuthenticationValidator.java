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

import java.util.function.Consumer;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

/**
 * A {@code Consumer} providing access to the {@link OidcLogoutAuthenticationContext}
 * containing an {@link OidcLogoutAuthenticationToken} and is the default
 * {@link OidcLogoutAuthenticationProvider#setAuthenticationValidator(Consumer)
 * authentication validator} used for validating specific OpenID Connect RP-Initiated
 * Logout Request parameters.
 *
 * <p>
 * The default implementation validates
 * {@link OidcLogoutAuthenticationToken#getPostLogoutRedirectUri()}. If validation fails,
 * an {@link OAuth2AuthenticationException} is thrown.
 *
 * @author Daniel Garnier-Moiroux
 * @since 1.4
 * @see OidcLogoutAuthenticationContext
 * @see OidcLogoutAuthenticationToken
 * @see OidcLogoutAuthenticationProvider#setAuthenticationValidator(Consumer)
 */
public final class OidcLogoutAuthenticationValidator implements Consumer<OidcLogoutAuthenticationContext> {

	/**
	 * The default validator for
	 * {@link OidcLogoutAuthenticationToken#getPostLogoutRedirectUri()}.
	 */
	public static final Consumer<OidcLogoutAuthenticationContext> DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR = OidcLogoutAuthenticationValidator::validatePostLogoutRedirectUri;

	private final Consumer<OidcLogoutAuthenticationContext> authenticationValidator = DEFAULT_POST_LOGOUT_REDIRECT_URI_VALIDATOR;

	@Override
	public void accept(OidcLogoutAuthenticationContext authenticationContext) {
		this.authenticationValidator.accept(authenticationContext);
	}

	private static void validatePostLogoutRedirectUri(OidcLogoutAuthenticationContext authenticationContext) {
		OidcLogoutAuthenticationToken oidcLogoutAuthentication = authenticationContext.getAuthentication();
		RegisteredClient registeredClient = authenticationContext.getRegisteredClient();
		if (StringUtils.hasText(oidcLogoutAuthentication.getPostLogoutRedirectUri())
				&& !registeredClient.getPostLogoutRedirectUris()
					.contains(oidcLogoutAuthentication.getPostLogoutRedirectUri())) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
					"OpenID Connect 1.0 Logout Request Parameter: post_logout_redirect_uri",
					"https://openid.net/specs/openid-connect-rpinitiated-1_0.html#ValidationAndErrorHandling");
			throw new OAuth2AuthenticationException(error);
		}
	}

}
