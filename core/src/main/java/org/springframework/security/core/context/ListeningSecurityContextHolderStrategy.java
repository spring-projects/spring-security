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

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiConsumer;
import java.util.function.Supplier;

final class ListeningSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final BiConsumer<SecurityContext, SecurityContext> NULL_PUBLISHER = (previous, current) -> {
	};

	private final Supplier<SecurityContext> peek;

	private final SecurityContextHolderStrategy delegate;

	private final SecurityContextEventPublisher base = new SecurityContextEventPublisher();

	private BiConsumer<SecurityContext, SecurityContext> publisher = NULL_PUBLISHER;

	ListeningSecurityContextHolderStrategy(Supplier<SecurityContext> peek, SecurityContextHolderStrategy delegate) {
		this.peek = peek;
		this.delegate = delegate;
	}

	@Override
	public void clearContext() {
		SecurityContext from = this.peek.get();
		this.delegate.clearContext();
		this.publisher.accept(from, null);
	}

	@Override
	public SecurityContext getContext() {
		return this.delegate.getContext();
	}

	@Override
	public void setContext(SecurityContext context) {
		SecurityContext from = this.peek.get();
		this.delegate.setContext(context);
		this.publisher.accept(from, context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return this.delegate.createEmptyContext();
	}

	void addListener(SecurityContextChangedListener listener) {
		this.base.listeners.add(listener);
		this.publisher = this.base;
	}

	private static class SecurityContextEventPublisher implements BiConsumer<SecurityContext, SecurityContext> {

		private final List<SecurityContextChangedListener> listeners = new CopyOnWriteArrayList<>();

		@Override
		public void accept(SecurityContext previous, SecurityContext current) {
			if (previous == current) {
				return;
			}
			SecurityContextChangedEvent event = new SecurityContextChangedEvent(previous, current);
			for (SecurityContextChangedListener listener : this.listeners) {
				listener.securityContextChanged(event);
			}
		}

	}

}
