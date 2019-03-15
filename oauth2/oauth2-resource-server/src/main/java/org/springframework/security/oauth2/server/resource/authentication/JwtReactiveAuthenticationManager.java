/*
 * Copyright 2002-2018 the original author or authors.
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

import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrorCodes;
import org.springframework.util.Assert;

/**
 * A {@link ReactiveAuthenticationManager} for Jwt tokens.
 *
 * @author Rob Winch
 * @since 5.1
 */
public final class JwtReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private final JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

	private final ReactiveJwtDecoder jwtDecoder;

	public JwtReactiveAuthenticationManager(ReactiveJwtDecoder jwtDecoder) {
		Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
		this.jwtDecoder = jwtDecoder;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Mono.justOrEmpty(authentication)
				.filter(a -> a instanceof  BearerTokenAuthenticationToken)
				.cast(BearerTokenAuthenticationToken.class)
				.map(BearerTokenAuthenticationToken::getToken)
				.flatMap(this.jwtDecoder::decode)
				.map(this.jwtAuthenticationConverter::convert)
				.cast(Authentication.class)
				.onErrorMap(JwtException.class, this::onError);
	}

	private OAuth2AuthenticationException onError(JwtException e) {
		OAuth2Error invalidRequest = invalidToken(e.getMessage());
		return new OAuth2AuthenticationException(invalidRequest, e.getMessage());
	}

	private static OAuth2Error invalidToken(String message) {
		return new BearerTokenError(
				BearerTokenErrorCodes.INVALID_TOKEN,
				HttpStatus.UNAUTHORIZED,
				message,
				"https://tools.ietf.org/html/rfc6750#section-3.1");
	}
}
