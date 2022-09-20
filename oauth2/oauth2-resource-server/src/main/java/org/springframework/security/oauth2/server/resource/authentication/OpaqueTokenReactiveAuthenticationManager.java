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

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.introspection.BadOpaqueTokenException;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.util.Assert;

/**
 * An {@link ReactiveAuthenticationManager} implementation for opaque
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>s, using an
 * <a href="https://tools.ietf.org/html/rfc7662" target="_blank">OAuth 2.0 Introspection
 * Endpoint</a> to check the token's validity and reveal its attributes.
 * <p>
 * This {@link ReactiveAuthenticationManager} is responsible for introspecting and
 * verifying an opaque access token, returning its attributes set as part of the
 * {@link Authentication} statement.
 * <p>
 * A {@link ReactiveOpaqueTokenIntrospector} is responsible for retrieving token
 * attributes from an authorization server.
 * <p>
 * A {@link ReactiveOpaqueTokenAuthenticationConverter} is responsible for turning a
 * successful introspection result into an {@link Authentication} instance (which may
 * include mapping {@link GrantedAuthority}s from token attributes or retrieving from
 * another source).
 *
 * @author Josh Cummings
 * @author Jerome Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2
 * @see ReactiveAuthenticationManager
 */
public class OpaqueTokenReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private final ReactiveOpaqueTokenIntrospector introspector;

	private ReactiveOpaqueTokenAuthenticationConverter authenticationConverter = OpaqueTokenReactiveAuthenticationManager::convert;

	/**
	 * Creates a {@code OpaqueTokenReactiveAuthenticationManager} with the provided
	 * parameters
	 * @param introspector The {@link ReactiveOpaqueTokenIntrospector} to use
	 */
	public OpaqueTokenReactiveAuthenticationManager(ReactiveOpaqueTokenIntrospector introspector) {
		Assert.notNull(introspector, "introspector cannot be null");
		this.introspector = introspector;
	}

	/**
	 * Introspect and validate the opaque
	 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
	 * Token</a> and then delegates {@link Authentication} instantiation to
	 * {@link ReactiveOpaqueTokenAuthenticationConverter}.
	 * <p>
	 * If created Authentication is instance of {@link AbstractAuthenticationToken} and
	 * details are null, then introspection result details are used.
	 * @param authentication the authentication request object.
	 * @return A successful authentication
	 */
	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		// @formatter:off
		return Mono.justOrEmpty(authentication)
				.filter(BearerTokenAuthenticationToken.class::isInstance)
				.cast(BearerTokenAuthenticationToken.class)
				.map(BearerTokenAuthenticationToken::getToken)
				.flatMap(this::authenticate);
		// @formatter:on
	}

	private Mono<Authentication> authenticate(String token) {
		// @formatter:off
		return this.introspector.introspect(token)
				.flatMap((principal) -> this.authenticationConverter.convert(token, principal))
				.onErrorMap(OAuth2IntrospectionException.class, this::onError);
		// @formatter:on
	}

	private AuthenticationException onError(OAuth2IntrospectionException ex) {
		if (ex instanceof BadOpaqueTokenException) {
			return new InvalidBearerTokenException(ex.getMessage(), ex);
		}
		return new AuthenticationServiceException(ex.getMessage(), ex);
	}

	/**
	 * Default {@link ReactiveOpaqueTokenAuthenticationConverter}.
	 * @param introspectedToken the bearer string that was successfully introspected
	 * @param authenticatedPrincipal the successful introspection output
	 * @return an async wrapper of default {@link OpaqueTokenAuthenticationConverter}
	 * result
	 */
	static Mono<Authentication> convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
		return Mono.just(OpaqueTokenAuthenticationProvider.convert(introspectedToken, authenticatedPrincipal));
	}

	/**
	 * Provide with a custom bean to turn successful introspection result into an
	 * {@link Authentication} instance of your choice. By default,
	 * {@link BearerTokenAuthentication} will be built.
	 * @param authenticationConverter the converter to use
	 * @since 5.8
	 */
	public void setAuthenticationConverter(ReactiveOpaqueTokenAuthenticationConverter authenticationConverter) {
		Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
		this.authenticationConverter = authenticationConverter;
	}

}
