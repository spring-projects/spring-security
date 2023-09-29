/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.web.server;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Mono;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * An {@link AuthenticationConverter} that extracts the OIDC Logout Token authentication
 * request
 *
 * @author Josh Cummings
 * @since 6.2
 */
final class OidcLogoutServerAuthenticationConverter implements ServerAuthenticationConverter {

	private static final String DEFAULT_LOGOUT_URI = "/logout/connect/back-channel/{registrationId}";

	private final Log logger = LogFactory.getLog(getClass());

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	private ServerWebExchangeMatcher exchangeMatcher = new PathPatternParserServerWebExchangeMatcher(DEFAULT_LOGOUT_URI,
			HttpMethod.POST);

	OidcLogoutServerAuthenticationConverter(ReactiveClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange exchange) {
		return this.exchangeMatcher.matches(exchange)
			.filter(ServerWebExchangeMatcher.MatchResult::isMatch)
			.flatMap((match) -> {
				String registrationId = (String) match.getVariables().get("registrationId");
				return this.clientRegistrationRepository.findByRegistrationId(registrationId)
					.switchIfEmpty(Mono.error(() -> {
						this.logger
							.debug("Did not process OIDC Back-Channel Logout since no ClientRegistration was found");
						return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
					}));
			})
			.flatMap((clientRegistration) -> exchange.getFormData().map((data) -> {
				String logoutToken = data.getFirst("logout_token");
				return new OidcLogoutAuthenticationToken(logoutToken, clientRegistration);
			}).switchIfEmpty(Mono.error(() -> {
				this.logger.debug("Failed to process OIDC Back-Channel Logout since no logout token was found");
				return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
			})));
	}

	/**
	 * The logout endpoint. Defaults to
	 * {@code /logout/connect/back-channel/{registrationId}}.
	 * @param exchangeMatcher the {@link ServerWebExchangeMatcher} to use
	 */
	void setExchangeMatcher(ServerWebExchangeMatcher exchangeMatcher) {
		Assert.notNull(exchangeMatcher, "exchangeMatcher cannot be null");
		this.exchangeMatcher = exchangeMatcher;
	}

}
