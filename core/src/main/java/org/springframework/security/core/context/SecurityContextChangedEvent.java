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

import java.util.function.Supplier;

import org.springframework.context.ApplicationEvent;

/**
 * An event that represents a change in {@link SecurityContext}
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class SecurityContextChangedEvent extends ApplicationEvent {

	public static final Supplier<SecurityContext> NO_CONTEXT = () -> null;

	private final Supplier<SecurityContext> oldContext;

	private final Supplier<SecurityContext> newContext;

	/**
	 * Construct an event
	 * @param oldContext the old security context
	 * @param newContext the new security context, use
	 * {@link SecurityContextChangedEvent#NO_CONTEXT} for if the context is cleared
	 * @since 5.8
	 */
	public SecurityContextChangedEvent(Supplier<SecurityContext> oldContext, Supplier<SecurityContext> newContext) {
		super(SecurityContextHolder.class);
		this.oldContext = oldContext;
		this.newContext = newContext;
	}

	/**
	 * Construct an event
	 * @param oldContext the old security context
	 * @param newContext the new security context
	 */
	public SecurityContextChangedEvent(SecurityContext oldContext, SecurityContext newContext) {
		this(() -> oldContext, (newContext != null) ? () -> newContext : NO_CONTEXT);
	}

	/**
	 * Get the {@link SecurityContext} set on the {@link SecurityContextHolder}
	 * immediately previous to this event
	 * @return the previous {@link SecurityContext}
	 */
	public SecurityContext getOldContext() {
		return this.oldContext.get();
	}

	/**
	 * Get the {@link SecurityContext} set on the {@link SecurityContextHolder} as of this
	 * event
	 * @return the current {@link SecurityContext}
	 */
	public SecurityContext getNewContext() {
		return this.newContext.get();
	}

	/**
	 * Say whether the event is a context-clearing event.
	 *
	 * <p>
	 * This method is handy for avoiding looking up the new context to confirm it is a
	 * cleared event.
	 * @return {@code true} if the new context is
	 * {@link SecurityContextChangedEvent#NO_CONTEXT}
	 * @since 5.8
	 */
	public boolean isCleared() {
		return this.newContext == NO_CONTEXT;
	}

}
