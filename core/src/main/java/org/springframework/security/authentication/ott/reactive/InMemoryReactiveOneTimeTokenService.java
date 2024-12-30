/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authentication.ott.reactive;

import java.time.Clock;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.InMemoryOneTimeTokenService;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.util.Assert;

/**
 * Reactive adapter for {@link InMemoryOneTimeTokenService}
 *
 * @author Max Batischev
 * @since 6.4
 * @see InMemoryOneTimeTokenService
 */
public final class InMemoryReactiveOneTimeTokenService implements ReactiveOneTimeTokenService {

	private final InMemoryOneTimeTokenService oneTimeTokenService = new InMemoryOneTimeTokenService();

	@Override
	public Mono<OneTimeToken> generate(GenerateOneTimeTokenRequest request) {
		return Mono.just(request).map(this.oneTimeTokenService::generate);
	}

	@Override
	public Mono<OneTimeToken> consume(OneTimeTokenAuthenticationToken authenticationToken) {
		return Mono.just(authenticationToken).mapNotNull(this.oneTimeTokenService::consume);
	}

	/**
	 * Sets the {@link Clock} used when generating one-time token and checking token
	 * expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.oneTimeTokenService.setClock(clock);
	}

}
