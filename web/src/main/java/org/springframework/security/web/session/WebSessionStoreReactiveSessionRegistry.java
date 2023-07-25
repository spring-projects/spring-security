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

package org.springframework.security.web.session;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.core.session.InMemoryReactiveSessionRegistry;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.ReactiveSessionRegistry;
import org.springframework.util.Assert;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.WebSessionStore;

/**
 * A {@link ReactiveSessionRegistry} implementation that uses a {@link WebSessionStore} to
 * invalidate a {@link WebSession} when the {@link ReactiveSessionInformation} is
 * invalidated.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class WebSessionStoreReactiveSessionRegistry implements ReactiveSessionRegistry {

	private final WebSessionStore webSessionStore;

	private ReactiveSessionRegistry sessionRegistry = new InMemoryReactiveSessionRegistry();

	public WebSessionStoreReactiveSessionRegistry(WebSessionStore webSessionStore) {
		Assert.notNull(webSessionStore, "webSessionStore cannot be null");
		this.webSessionStore = webSessionStore;
	}

	@Override
	public Flux<ReactiveSessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		return this.sessionRegistry.getAllSessions(principal, includeExpiredSessions).map(WebSessionInformation::new);
	}

	@Override
	public Mono<Void> saveSessionInformation(ReactiveSessionInformation information) {
		return this.sessionRegistry.saveSessionInformation(new WebSessionInformation(information));
	}

	@Override
	public Mono<ReactiveSessionInformation> getSessionInformation(String sessionId) {
		return this.sessionRegistry.getSessionInformation(sessionId).map(WebSessionInformation::new);
	}

	@Override
	public Mono<ReactiveSessionInformation> removeSessionInformation(String sessionId) {
		return this.sessionRegistry.removeSessionInformation(sessionId).map(WebSessionInformation::new);
	}

	@Override
	public Mono<ReactiveSessionInformation> updateLastAccessTime(String sessionId) {
		return this.sessionRegistry.updateLastAccessTime(sessionId).map(WebSessionInformation::new);
	}

	/**
	 * Sets the {@link ReactiveSessionRegistry} to use.
	 * @param sessionRegistry the {@link ReactiveSessionRegistry} to use. Cannot be null.
	 */
	public void setSessionRegistry(ReactiveSessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	final class WebSessionInformation extends ReactiveSessionInformation {

		WebSessionInformation(ReactiveSessionInformation sessionInformation) {
			super(sessionInformation.getPrincipal(), sessionInformation.getSessionId(),
					sessionInformation.getLastAccessTime());
		}

		@Override
		public Mono<Void> invalidate() {
			return WebSessionStoreReactiveSessionRegistry.this.webSessionStore.retrieveSession(getSessionId())
				.flatMap(WebSession::invalidate)
				.then(Mono
					.defer(() -> WebSessionStoreReactiveSessionRegistry.this.removeSessionInformation(getSessionId())))
				.then(Mono.defer(super::invalidate));
		}

	}

}
