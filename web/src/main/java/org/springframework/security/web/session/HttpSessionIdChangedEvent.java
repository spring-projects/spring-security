/*
 * Copyright 2002-2020 the original author or authors.
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

import org.springframework.security.core.session.SessionIdChangedEvent;

import javax.servlet.http.HttpSession;

/**
 * Published by the {@link HttpSessionEventPublisher} when an {@link HttpSession} ID is
 * changed.
 *
 * @since 5.4
 */
public class HttpSessionIdChangedEvent extends SessionIdChangedEvent {

	private final String oldSessionId;

	private final String newSessionId;

	public HttpSessionIdChangedEvent(HttpSession session, String oldSessionId) {
		super(session);
		this.oldSessionId = oldSessionId;
		this.newSessionId = session.getId();
	}

	@Override
	public String getOldSessionId() {
		return oldSessionId;
	}

	@Override
	public String getNewSessionId() {
		return newSessionId;
	}

}
