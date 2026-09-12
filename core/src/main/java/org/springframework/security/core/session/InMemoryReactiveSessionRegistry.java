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

package org.springframework.security.core.session;

import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Provides an in-memory implementation of {@link ReactiveSessionRegistry}.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public class InMemoryReactiveSessionRegistry implements ReactiveSessionRegistry {

	private final ConcurrentMap<Object, Set<String>> sessionIdsByPrincipal;

	private final Map<String, ReactiveSessionInformation> sessionById;

	public InMemoryReactiveSessionRegistry() {
		this.sessionIdsByPrincipal = new ConcurrentHashMap<>();
		this.sessionById = new ConcurrentHashMap<>();
	}

	public InMemoryReactiveSessionRegistry(ConcurrentMap<Object, Set<String>> sessionIdsByPrincipal,
			Map<String, ReactiveSessionInformation> sessionById) {
		this.sessionIdsByPrincipal = sessionIdsByPrincipal;
		this.sessionById = sessionById;
	}

	@Override
	@SuppressWarnings("NullAway") // https://github.com/uber/NullAway/issues/1290
	public Flux<ReactiveSessionInformation> getAllSessions(Object principal) {
		return Flux.fromIterable(this.sessionIdsByPrincipal.getOrDefault(principal, Collections.emptySet()))
			.mapNotNull(this.sessionById::get);
	}

	@Override
	public Mono<Void> saveSessionInformation(ReactiveSessionInformation information) {
		this.sessionById.put(information.getSessionId(), information);
		// Add the session id inside the compute so that it cannot race with the key
		// removal performed by removeSessionInformation (which could otherwise drop a
		// concurrently added session). This mirrors the blocking SessionRegistryImpl.
		this.sessionIdsByPrincipal.compute(information.getPrincipal(), (key, sessionsUsedByPrincipal) -> {
			if (sessionsUsedByPrincipal == null) {
				sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			}
			sessionsUsedByPrincipal.add(information.getSessionId());
			return sessionsUsedByPrincipal;
		});
		return Mono.empty();
	}

	@Override
	public Mono<ReactiveSessionInformation> getSessionInformation(String sessionId) {
		return Mono.justOrEmpty(this.sessionById.get(sessionId));
	}

	@Override
	public Mono<ReactiveSessionInformation> removeSessionInformation(String sessionId) {
		return getSessionInformation(sessionId).doOnNext((sessionInformation) -> {
			this.sessionById.remove(sessionId);
			// Remove and prune atomically so the principal key is dropped only while its
			// set is empty; otherwise a session added concurrently could be lost. Mirrors
			// the blocking SessionRegistryImpl.
			this.sessionIdsByPrincipal.computeIfPresent(sessionInformation.getPrincipal(),
					(key, sessionsUsedByPrincipal) -> {
						sessionsUsedByPrincipal.remove(sessionId);
						return sessionsUsedByPrincipal.isEmpty() ? null : sessionsUsedByPrincipal;
					});
		});
	}

	@Override
	public Mono<ReactiveSessionInformation> updateLastAccessTime(String sessionId) {
		ReactiveSessionInformation session = this.sessionById.get(sessionId);
		if (session != null) {
			return session.refreshLastRequest().thenReturn(session);
		}
		return Mono.empty();
	}

}
