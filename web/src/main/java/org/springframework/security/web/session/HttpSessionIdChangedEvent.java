/*
 * Copyright 2002-2025 the original author or authors.
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

import java.io.Serial;

import jakarta.servlet.http.HttpSession;

import org.springframework.security.core.session.SessionIdChangedEvent;

/**
 * Published by the {@link HttpSessionEventPublisher} when an {@link HttpSession} ID is
 * changed.
 *
 * @since 5.4
 */
@SuppressWarnings("serial")
public class HttpSessionIdChangedEvent extends SessionIdChangedEvent {

	@Serial
	private static final long serialVersionUID = -5725731666499807941L;

	private final String oldSessionId;

	private final String newSessionId;

	public HttpSessionIdChangedEvent(HttpSession session, String oldSessionId) {
		super(session);
		this.oldSessionId = oldSessionId;
		this.newSessionId = session.getId();
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
