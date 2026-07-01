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

package org.springframework.security.web.authentication.session;

import java.io.Serial;

import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.session.SessionIdChangedEvent;

/**
 * Published by {@link AbstractSessionFixationProtectionStrategy} when a session ID
 * changes during session fixation protection. This allows
 * {@link org.springframework.security.core.session.SessionRegistryImpl} to track the
 * session ID change without requiring
 * {@link org.springframework.security.web.session.HttpSessionEventPublisher} to be
 * registered.
 *
 * @author Adolfo Gonzalez
 * @since 6.5
 * @see AbstractSessionFixationProtectionStrategy
 */
class SessionFixationProtectionSessionIdChangedEvent extends SessionIdChangedEvent {

	@Serial
	private static final long serialVersionUID = 1L;

	private final String oldSessionId;

	private final String newSessionId;

	SessionFixationProtectionSessionIdChangedEvent(HttpSession newSession, String oldSessionId) {
		super(newSession);
		this.oldSessionId = oldSessionId;
		this.newSessionId = newSession.getId();
	}

	@Override
	public String getOldSessionId() {
		return this.oldSessionId;
	}

	@Override
	public String getNewSessionId() {
		return this.newSessionId;
	}

}
