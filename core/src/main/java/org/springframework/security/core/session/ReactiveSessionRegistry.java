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

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Maintains a registry of {@link ReactiveSessionInformation} instances.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public interface ReactiveSessionRegistry {

	/**
	 * Gets all the known {@link ReactiveSessionInformation} instances for the specified
	 * principal.
	 * @param principal the principal
	 * @return the {@link ReactiveSessionInformation} instances associated with the
	 * principal
	 */
	Flux<ReactiveSessionInformation> getAllSessions(Object principal);

	/**
	 * Saves the {@link ReactiveSessionInformation}
	 * @param information the {@link ReactiveSessionInformation} to save
	 * @return a {@link Mono} that completes when the session is saved
	 */
	Mono<Void> saveSessionInformation(ReactiveSessionInformation information);

	/**
	 * Gets the {@link ReactiveSessionInformation} for the specified session identifier.
	 * @param sessionId the session identifier
	 * @return the {@link ReactiveSessionInformation} for the session.
	 */
	Mono<ReactiveSessionInformation> getSessionInformation(String sessionId);

	/**
	 * Removes the specified session from the registry.
	 * @param sessionId the session identifier
	 * @return a {@link Mono} that completes when the session is removed
	 */
	Mono<ReactiveSessionInformation> removeSessionInformation(String sessionId);

	/**
	 * Updates the last accessed time of the {@link ReactiveSessionInformation}
	 * @param sessionId the session identifier
	 * @return a {@link Mono} that completes when the session is updated
	 */
	Mono<ReactiveSessionInformation> updateLastAccessTime(String sessionId);

}
