/*
 * Copyright 2002-2019 the original author or authors.
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

import reactor.core.publisher.Mono;

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.util.Assert;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;

/**
 * An {@link ReactiveAuthenticationManager} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer Token</a>s,
 * using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection Endpoint</a>
 * to check the token's validity and reveal its attributes.
 * <p>
 * This {@link ReactiveAuthenticationManager} is responsible for introspecting and verifying an opaque access token,
 * returning its attributes set as part of the {@link Authentication} statement.
 * <p>
 * Scopes are translated into {@link GrantedAuthority}s according to the following algorithm:
 * <ol>
 * <li>
 * If there is a "scope" attribute, then convert to a {@link Collection} of {@link String}s.
 * <li>
 * Take the resulting {@link Collection} and prepend the "SCOPE_" keyword to each element, adding as {@link GrantedAuthority}s.
 * </ol>
 *
 * @author Josh Cummings
 * @since 5.2
 * @see ReactiveAuthenticationManager
 */
public class OpaqueTokenReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private static final BearerTokenError DEFAULT_INVALID_TOKEN =
			invalidToken("An error occurred while attempting to introspect the token: Invalid token");

	private ReactiveOpaqueTokenIntrospector introspector;

	/**
	 * Creates a {@code OpaqueTokenReactiveAuthenticationManager} with the provided parameters
	 *
	 * @param introspector The {@link ReactiveOpaqueTokenIntrospector} to use
	 */
	public OpaqueTokenReactiveAuthenticationManager(ReactiveOpaqueTokenIntrospector introspector) {
		Assert.notNull(introspector, "introspector cannot be null");
		this.introspector = introspector;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.justOrEmpty(authentication)
				.filter(BearerTokenAuthenticationToken.class::isInstance)
				.cast(BearerTokenAuthenticationToken.class)
				.map(BearerTokenAuthenticationToken::getToken)
				.flatMap(this::authenticate)
				.cast(Authentication.class);
	}

	private Mono<BearerTokenAuthentication> authenticate(String token) {
		return this.introspector.introspect(token)
				.map(principal -> {
					Instant iat = principal.getAttribute(ISSUED_AT);
					Instant exp = principal.getAttribute(EXPIRES_AT);

					// construct token
					OAuth2AccessToken accessToken =
							new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, token, iat, exp);
					return new BearerTokenAuthentication(principal, accessToken, principal.getAuthorities());
				})
				.onErrorMap(OAuth2IntrospectionException.class, this::onError);
	}

	private static BearerTokenError invalidToken(String message) {
		try {
			return new BearerTokenError("invalid_token",
					HttpStatus.UNAUTHORIZED, message,
					"https://tools.ietf.org/html/rfc7662#section-2.2");
		} catch (IllegalArgumentException e) {
			// some third-party library error messages are not suitable for RFC 6750's error message charset
			return DEFAULT_INVALID_TOKEN;
		}
	}

	private OAuth2AuthenticationException onError(OAuth2IntrospectionException e) {
		OAuth2Error invalidRequest = invalidToken(e.getMessage());
		return new OAuth2AuthenticationException(invalidRequest, e.getMessage());
	}
}
