/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * Indicates a session ID was changed for the purposes of session fixation protection.
 *
 * @author Nicholas Williams
 * @since 3.2
 * @see SessionFixationProtectionStrategy
 */
public class SessionFixationProtectionEvent extends AbstractAuthenticationEvent {

	private final String oldSessionId;

	private final String newSessionId;

	/**
	 * Constructs a new session fixation protection event.
	 * @param authentication The authentication object
	 * @param oldSessionId The old session ID before it was changed
	 * @param newSessionId The new session ID after it was changed
	 */
	public SessionFixationProtectionEvent(Authentication authentication, String oldSessionId, String newSessionId) {
		super(authentication);
		Assert.hasLength(oldSessionId, "oldSessionId must have length");
		Assert.hasLength(newSessionId, "newSessionId must have length");
		this.oldSessionId = oldSessionId;
		this.newSessionId = newSessionId;
	}

	/**
	 * Getter for the session ID before it was changed.
	 * @return the old session ID.
	 */
	public String getOldSessionId() {
		return this.oldSessionId;
	}

	/**
	 * Getter for the session ID after it was changed.
	 * @return the new session ID.
	 */
	public String getNewSessionId() {
		return this.newSessionId;
	}

}
