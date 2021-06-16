/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.core.context;

import org.springframework.context.ApplicationEvent;

/**
 * An event that represents a change in {@link SecurityContext}
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class SecurityContextChangedEvent extends ApplicationEvent {

	private final SecurityContext previous;

	private final SecurityContext current;

	/**
	 * Construct an event
	 * @param previous the old security context
	 * @param current the new security context
	 */
	public SecurityContextChangedEvent(SecurityContext previous, SecurityContext current) {
		super(SecurityContextHolder.class);
		this.previous = previous;
		this.current = current;
	}

	/**
	 * Get the {@link SecurityContext} set on the {@link SecurityContextHolder}
	 * immediately previous to this event
	 * @return the previous {@link SecurityContext}
	 */
	public SecurityContext getPreviousContext() {
		return this.previous;
	}

	/**
	 * Get the {@link SecurityContext} set on the {@link SecurityContextHolder} as of this
	 * event
	 * @return the current {@link SecurityContext}
	 */
	public SecurityContext getCurrentContext() {
		return this.current;
	}

}
