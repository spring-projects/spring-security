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

package org.springframework.security.web.server.authentication.ott;

import java.net.URI;

import reactor.core.publisher.Mono;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ServerOneTimeTokenGenerationSuccessHandler} that performs a redirect to a
 * specific location
 *
 * @author Max Batischev
 * @since 6.4
 */
public final class ServerRedirectOneTimeTokenGenerationSuccessHandler
		implements ServerOneTimeTokenGenerationSuccessHandler {

	private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

	private final URI redirectUri;

	public ServerRedirectOneTimeTokenGenerationSuccessHandler(String redirectUri) {
		Assert.hasText(redirectUri, "redirectUri cannot be empty or null");
		this.redirectUri = URI.create(redirectUri);
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, OneTimeToken oneTimeToken) {
		return this.redirectStrategy.sendRedirect(exchange, this.redirectUri);
	}

}
