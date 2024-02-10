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

package org.springframework.security.web.server.authentication;

import reactor.core.publisher.Mono;

/**
 * Strategy for handling the scenario when the maximum number of sessions for a user has
 * been reached.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public interface ServerMaximumSessionsExceededHandler {

	/**
	 * Handles the scenario when the maximum number of sessions for a user has been
	 * reached.
	 * @param context the context with information about the sessions and the user
	 * @return an empty {@link Mono} that completes when the handling is done
	 */
	Mono<Void> handle(MaximumSessionsContext context);

}
