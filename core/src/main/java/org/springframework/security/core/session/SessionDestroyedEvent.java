/*
 * Copyright 2002-2016 the original author or authors.
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

import org.springframework.context.ApplicationEvent;
import org.springframework.security.core.context.SecurityContext;

import java.util.*;

/**
 * Generic "session termination" event which indicates that a session (potentially
 * represented by a security context) has ended.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public abstract class SessionDestroyedEvent extends ApplicationEvent {

	public SessionDestroyedEvent(Object source) {
		super(source);
	}

	/**
	 * Provides the {@code SecurityContext} instances which were associated with the
	 * destroyed session. Usually there will be only one security context per session.
	 *
	 * @return the {@code SecurityContext} instances which were stored in the current
	 * session (an empty list if there are none).
	 */
	public abstract List<SecurityContext> getSecurityContexts();

	/**
	 * @return the identifier associated with the destroyed session.
	 */
	public abstract String getId();
}
