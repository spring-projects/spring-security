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
	public Flux<ReactiveSessionInformation> getAllSessions(Object principal) {
		return Flux.fromIterable(this.sessionIdsByPrincipal.getOrDefault(principal, Collections.emptySet()))
			.map(this.sessionById::get);
	}

	@Override
	public Mono<Void> saveSessionInformation(ReactiveSessionInformation information) {
		this.sessionById.put(information.getSessionId(), information);
		this.sessionIdsByPrincipal.computeIfAbsent(information.getPrincipal(), (key) -> new CopyOnWriteArraySet<>())
			.add(information.getSessionId());
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
			Set<String> sessionsUsedByPrincipal = this.sessionIdsByPrincipal.get(sessionInformation.getPrincipal());
			if (sessionsUsedByPrincipal != null) {
				sessionsUsedByPrincipal.remove(sessionId);
				if (sessionsUsedByPrincipal.isEmpty()) {
					this.sessionIdsByPrincipal.remove(sessionInformation.getPrincipal());
				}
			}
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
