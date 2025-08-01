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

package org.springframework.security.web.server.authentication.ott;

import java.time.Duration;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Default implementation of {@link ServerGenerateOneTimeTokenRequestResolver}. Resolves
 * {@link GenerateOneTimeTokenRequest} from username parameter.
 *
 * @author Max Batischev
 * @since 6.5
 */
public final class DefaultServerGenerateOneTimeTokenRequestResolver
		implements ServerGenerateOneTimeTokenRequestResolver {

	private static final String USERNAME = "username";

	private static final Duration DEFAULT_EXPIRES_IN = Duration.ofMinutes(5);

	private Duration expiresIn = DEFAULT_EXPIRES_IN;

	@Override
	public Mono<GenerateOneTimeTokenRequest> resolve(ServerWebExchange exchange) {
		// @formatter:off
		return exchange.getFormData()
				.mapNotNull((data) -> data.getFirst(USERNAME))
				.switchIfEmpty(Mono.empty())
				.map((username) -> new GenerateOneTimeTokenRequest(username, this.expiresIn));
		// @formatter:on
	}

	/**
	 * Sets one-time token expiration time
	 * @param expiresIn one-time token expiration time
	 */
	public void setExpiresIn(Duration expiresIn) {
		Assert.notNull(expiresIn, "expiresIn cannot be null");
		this.expiresIn = expiresIn;
	}

}
