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

package org.springframework.security.config.test;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * {@link RequestPostProcessor}s for simulating an incoming session in tests.
 *
 * @author Josh Cummings
 */
public final class SessionRequestPostProcessors {

	private SessionRequestPostProcessors() {
	}

	/**
	 * Simulate a client that already holds {@code session}, as though it were established
	 * by an earlier request. Unlike
	 * {@link org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder#session},
	 * this also marks the session's id as the one requested by the client, which is
	 * required for
	 * {@link jakarta.servlet.http.HttpServletRequest#isRequestedSessionIdValid()} to
	 * reflect a returning client instead of one with no session at all.
	 * @param session the pre-existing session to simulate
	 */
	public static RequestPostProcessor requestedSession(MockHttpSession session) {
		return (request) -> {
			request.setSession(session);
			request.setRequestedSessionId(session.getId());
			return request;
		};
	}

}
