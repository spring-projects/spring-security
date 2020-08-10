/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.oauth2.server.resource.authentication;

import java.time.Instant;
import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

/**
 * An {@link AuthenticationProvider} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>s, using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a> to check the token's validity and reveal its attributes.
 * <p>
 * This {@link AuthenticationProvider} is responsible for introspecting and verifying an
 * opaque access token, returning its attributes set as part of the {@link Authentication}
 * statement.
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following
 * algorithm:
 * <ol>
 * <li>If there is a "scope" attribute, then convert to a {@link Collection} of
 * {@link String}s.
 * <li>Take the resulting {@link Collection} and prepend the "SCOPE_" keyword to each
 * element, adding as {@link GrantedAuthority}s.
 * </ol>
 *
 * @author Josh Cummings
 * @since 5.2
 * @see AuthenticationProvider
 */
public final class OpaqueTokenAuthenticationProvider implements AuthenticationProvider {

	private OpaqueTokenIntrospector introspector;

	/**
	 * Creates a {@code OpaqueTokenAuthenticationProvider} with the provided parameters
	 * @param introspector The {@link OpaqueTokenIntrospector} to use
	 */
	public OpaqueTokenAuthenticationProvider(OpaqueTokenIntrospector introspector) {
		Assert.notNull(introspector, "introspector cannot be null");
		this.introspector = introspector;
	}

	/**
	 * Introspect and validate the opaque
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a>.
	 * @param authentication the authentication request object.
	 * @return A successful authentication
	 * @throws AuthenticationException if authentication failed for some reason
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!(authentication instanceof BearerTokenAuthenticationToken)) {
			return null;
		}
		BearerTokenAuthenticationToken bearer = (BearerTokenAuthenticationToken) authentication;

		OAuth2AuthenticatedPrincipal principal;
		try {
			principal = this.introspector.introspect(bearer.getToken());
		}
		catch (BadOpaqueTokenException failed) {
			throw new InvalidBearerTokenException(failed.getMessage());
		}
		catch (OAuth2IntrospectionException failed) {
			throw new AuthenticationServiceException(failed.getMessage());
		}

		AbstractAuthenticationToken result = convert(principal, bearer.getToken());
		result.setDetails(bearer.getDetails());
		return result;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private AbstractAuthenticationToken convert(OAuth2AuthenticatedPrincipal principal, String token) {
		Instant iat = principal.getAttribute(ISSUED_AT);
		Instant exp = principal.getAttribute(EXPIRES_AT);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, iat, exp);
		return new BearerTokenAuthentication(principal, accessToken, principal.getAuthorities());
	}

}
