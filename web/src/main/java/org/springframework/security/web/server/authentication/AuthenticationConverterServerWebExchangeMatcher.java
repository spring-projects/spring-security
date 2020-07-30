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

package org.springframework.security.web.server.authentication;

import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Matches if the {@link ServerAuthenticationConverter} can convert a
 * {@link ServerWebExchange} to an {@link Authentication}.
 *
 * @author David Kovac
 * @since 5.4
 * @see ServerAuthenticationConverter
 */
public final class AuthenticationConverterServerWebExchangeMatcher implements ServerWebExchangeMatcher {

	private final ServerAuthenticationConverter serverAuthenticationConverter;

	public AuthenticationConverterServerWebExchangeMatcher(
			ServerAuthenticationConverter serverAuthenticationConverter) {
		Assert.notNull(serverAuthenticationConverter, "serverAuthenticationConverter cannot be null");
		this.serverAuthenticationConverter = serverAuthenticationConverter;
	}

	@Override
	public Mono<MatchResult> matches(ServerWebExchange exchange) {
		return this.serverAuthenticationConverter.convert(exchange).flatMap((a) -> MatchResult.match())
				.onErrorResume((e) -> MatchResult.notMatch()).switchIfEmpty(MatchResult.notMatch());
	}

}
