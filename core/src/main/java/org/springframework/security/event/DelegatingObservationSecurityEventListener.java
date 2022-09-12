/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.event;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.core.convert.converter.Converter;
import org.springframework.util.Assert;

/**
 * A {@link ApplicationListener} that publishes {@link SecurityEvent}s to an
 * {@link io.micrometer.observation.ObservationRegistry}
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class DelegatingObservationSecurityEventListener implements ApplicationListener<SecurityEvent> {

	private final Collection<SmartApplicationListener> listeners;

	private DelegatingObservationSecurityEventListener(Collection<SmartApplicationListener> listeners) {
		this.listeners = listeners;
	}

	public static Builder withDefaults(ObservationRegistry registry) {
		Assert.notNull(registry, "registry cannot be null");
		return new Builder(registry);
	}

	@Override
	public void onApplicationEvent(SecurityEvent event) {
		for (SmartApplicationListener listener : this.listeners) {
			Object source = event.getSource();
			if (source != null && listener.supportsEventType(event.getClass())
					&& listener.supportsSourceType(source.getClass())) {
				listener.onApplicationEvent(event);
				return;
			}
		}
	}

	public static final class Builder {

		private final ObservationRegistry registry;

		private final Map<String, SmartApplicationListener> listeners;

		private Builder(ObservationRegistry registry) {
			this.registry = registry;
			this.listeners = new LinkedHashMap<>();
		}

		public <T extends SecurityEvent> Builder add(Class<T> clazz) {
			return add(clazz, (event) -> KeyValues.empty());
		}

		public <T extends SecurityEvent> Builder add(Class<T> clazz, Converter<T, KeyValues> keyValuesConverter) {
			return add(clazz, new ObservationSecurityEventListener<>(this.registry, keyValuesConverter));
		}

		public <T extends SecurityEvent> Builder add(Class<T> clazz, ObservationSecurityEventListener<T> listener) {
			this.listeners.put(clazz.getName(), new SecuritySmartApplicationListener<>(clazz, listener));
			return this;
		}

		public DelegatingObservationSecurityEventListener build() {
			add(SecurityEvent.class);
			return new DelegatingObservationSecurityEventListener(this.listeners.values());
		}

		private static class SecuritySmartApplicationListener<T extends SecurityEvent>
				implements SmartApplicationListener {

			private final Class<T> eventType;

			private final ApplicationListener<T> listener;

			SecuritySmartApplicationListener(Class<T> eventType, ApplicationListener<T> listener) {
				this.eventType = eventType;
				this.listener = listener;
			}

			@Override
			public boolean supportsEventType(Class<? extends ApplicationEvent> eventType) {
				return this.eventType.isAssignableFrom(eventType);
			}

			@Override
			public void onApplicationEvent(ApplicationEvent event) {
				this.listener.onApplicationEvent((T) event);
			}

		}

	}

}
