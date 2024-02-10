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

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.session.ReactiveSessionInformation;

/**
 * Implementation of {@link ServerMaximumSessionsExceededHandler} that invalidates the
 * least recently used session(s). It only invalidates the amount of sessions that exceed
 * the maximum allowed. For example, if the maximum was exceeded by 1, only the least
 * recently used session will be invalidated.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public final class InvalidateLeastUsedServerMaximumSessionsExceededHandler
		implements ServerMaximumSessionsExceededHandler {

	private final Log logger = LogFactory.getLog(getClass());

	@Override
	public Mono<Void> handle(MaximumSessionsContext context) {
		List<ReactiveSessionInformation> sessions = new ArrayList<>(context.getSessions());
		sessions.sort(Comparator.comparing(ReactiveSessionInformation::getLastAccessTime));
		int maximumSessionsExceededBy = sessions.size() - context.getMaximumSessionsAllowed() + 1;
		List<ReactiveSessionInformation> leastRecentlyUsedSessionsToInvalidate = sessions.subList(0,
				maximumSessionsExceededBy);

		return Flux.fromIterable(leastRecentlyUsedSessionsToInvalidate)
			.doOnComplete(() -> this.logger
				.debug(LogMessage.format("Invalidated %d least recently used sessions for authentication %s",
						leastRecentlyUsedSessionsToInvalidate.size(), context.getAuthentication().getName())))
			.flatMap(ReactiveSessionInformation::invalidate)
			.then();
	}

}
