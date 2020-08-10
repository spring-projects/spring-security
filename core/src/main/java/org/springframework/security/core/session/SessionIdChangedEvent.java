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
package org.springframework.security.core.session;

/**
 * Generic "session ID changed" event which indicates that a session identifier
 * (potentially represented by a security context) has changed.
 *
 * @since 5.4
 */
public abstract class SessionIdChangedEvent extends AbstractSessionEvent {

	public SessionIdChangedEvent(Object source) {
		super(source);
	}

	/**
	 * Returns the old session ID.
	 * @return the identifier that was previously associated with the session.
	 */
	public abstract String getOldSessionId();

	/**
	 * Returns the new session ID.
	 * @return the new identifier that is associated with the session.
	 */
	public abstract String getNewSessionId();

}
