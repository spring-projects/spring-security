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

package org.springframework.security.oauth2.client.oidc.server.session;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.oauth2.client.oidc.authentication.logout.OidcLogoutToken;
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry;
import org.springframework.security.oauth2.client.oidc.session.OidcSessionInformation;

/**
 * An in-memory implementation of
 * {@link org.springframework.security.oauth2.client.oidc.server.session.ReactiveOidcSessionRegistry}
 *
 * @author Josh Cummings
 * @since 6.2
 */
public final class InMemoryReactiveOidcSessionRegistry implements ReactiveOidcSessionRegistry {

	private final InMemoryOidcSessionRegistry delegate = new InMemoryOidcSessionRegistry();

	@Override
	public Mono<Void> saveSessionInformation(OidcSessionInformation info) {
		this.delegate.saveSessionInformation(info);
		return Mono.empty();
	}

	@Override
	public Mono<OidcSessionInformation> removeSessionInformation(String clientSessionId) {
		return Mono.justOrEmpty(this.delegate.removeSessionInformation(clientSessionId));
	}

	@Override
	public Flux<OidcSessionInformation> removeSessionInformation(OidcLogoutToken token) {
		return Flux.fromIterable(this.delegate.removeSessionInformation(token));
	}

}
