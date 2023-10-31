/*
 * Copyright 2002-2022 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.util.Assert;

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
 * <p>
 * An {@link OpaqueTokenIntrospector} is responsible for retrieving token attributes from
 * an authorization server.
 * <p>
 * An {@link OpaqueTokenAuthenticationConverter} is responsible for turning a successful
 * introspection result into an {@link Authentication} instance (which may include mapping
 * {@link GrantedAuthority}s from token attributes or retrieving from another source).
 *
 * @author Josh Cummings
 * @author Jerome Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2
 * @see AuthenticationProvider
 */
public final class OpaqueTokenAuthenticationProvider implements AuthenticationProvider {

	private final Log logger = LogFactory.getLog(getClass());

	private final OpaqueTokenIntrospector introspector;

	private OpaqueTokenAuthenticationConverter authenticationConverter = OpaqueTokenAuthenticationProvider::convert;

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
	 * Token</a> and then delegates {@link Authentication} instantiation to
	 * {@link OpaqueTokenAuthenticationConverter}.
	 * <p>
	 * If created Authentication is instance of {@link AbstractAuthenticationToken} and
	 * details are null, then introspection result details are used.
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
		OAuth2AuthenticatedPrincipal principal = getOAuth2AuthenticatedPrincipal(bearer);
		Authentication result = this.authenticationConverter.convert(bearer.getToken(), principal);
		if (result == null) {
			return null;
		}
		if (AbstractAuthenticationToken.class.isAssignableFrom(result.getClass())) {
			final AbstractAuthenticationToken auth = (AbstractAuthenticationToken) result;
			if (auth.getDetails() == null) {
				auth.setDetails(bearer.getDetails());
			}
		}
		this.logger.debug("Authenticated token");
		return result;
	}

	private OAuth2AuthenticatedPrincipal getOAuth2AuthenticatedPrincipal(BearerTokenAuthenticationToken bearer) {
		try {
			return this.introspector.introspect(bearer.getToken());
		}
		catch (BadOpaqueTokenException failed) {
			this.logger.debug("Failed to authenticate since token was invalid");
			throw new InvalidBearerTokenException(failed.getMessage(), failed);
		}
		catch (OAuth2IntrospectionException failed) {
			throw new AuthenticationServiceException(failed.getMessage(), failed);
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return BearerTokenAuthenticationToken.class.isAssignableFrom(authentication);
	}

	/**
	 * Default {@link OpaqueTokenAuthenticationConverter}.
	 * @param introspectedToken the bearer string that was successfully introspected
	 * @param authenticatedPrincipal the successful introspection output
	 * @return a {@link BearerTokenAuthentication}
	 */
	static BearerTokenAuthentication convert(String introspectedToken,
			OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
		Instant iat = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.IAT);
		Instant exp = authenticatedPrincipal.getAttribute(OAuth2TokenIntrospectionClaimNames.EXP);
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, introspectedToken,
				iat, exp);
		return new BearerTokenAuthentication(authenticatedPrincipal, accessToken,
				authenticatedPrincipal.getAuthorities());
	}

	/**
	 * Provide with a custom bean to turn successful introspection result into an
	 * {@link Authentication} instance of your choice. By default,
	 * {@link BearerTokenAuthentication} will be built.
	 * @param authenticationConverter the converter to use
	 * @since 5.8
	 */
	public void setAuthenticationConverter(OpaqueTokenAuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

}
