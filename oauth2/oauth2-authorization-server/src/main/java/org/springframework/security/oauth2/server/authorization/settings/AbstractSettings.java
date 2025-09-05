/*
 * Copyright 2020-2025 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.settings;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

import org.springframework.util.Assert;

/**
 * Base implementation for configuration settings.
 *
 * @author Joe Grandja
 * @since 0.0.2
 */
public abstract class AbstractSettings implements Serializable {

	@Serial
	private static final long serialVersionUID = 7434920549178503670L;

	private final Map<String, Object> settings;

	protected AbstractSettings(Map<String, Object> settings) {
		Assert.notEmpty(settings, "settings cannot be empty");
		this.settings = Collections.unmodifiableMap(new HashMap<>(settings));
	}

	/**
	 * Returns a configuration setting.
	 * @param name the name of the setting
	 * @param <T> the type of the setting
	 * @return the value of the setting, or {@code null} if not available
	 */
	@SuppressWarnings("unchecked")
	public <T> T getSetting(String name) {
		Assert.hasText(name, "name cannot be empty");
		return (T) getSettings().get(name);
	}

	/**
	 * Returns a {@code Map} of the configuration settings.
	 * @return a {@code Map} of the configuration settings
	 */
	public Map<String, Object> getSettings() {
		return this.settings;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || getClass() != obj.getClass()) {
			return false;
		}
		AbstractSettings that = (AbstractSettings) obj;
		return this.settings.equals(that.settings);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.settings);
	}

	@Override
	public String toString() {
		return "AbstractSettings {" + "settings=" + this.settings + '}';
	}

	/**
	 * A builder for subclasses of {@link AbstractSettings}.
	 *
	 * @param <T> the type of object
	 * @param <B> the type of the builder
	 */
	protected abstract static class AbstractBuilder<T extends AbstractSettings, B extends AbstractBuilder<T, B>> {

		private final Map<String, Object> settings = new HashMap<>();

		protected AbstractBuilder() {
		}

		/**
		 * Sets a configuration setting.
		 * @param name the name of the setting
		 * @param value the value of the setting
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B setting(String name, Object value) {
			Assert.hasText(name, "name cannot be empty");
			Assert.notNull(value, "value cannot be null");
			getSettings().put(name, value);
			return getThis();
		}

		/**
		 * A {@code Consumer} of the configuration settings {@code Map} allowing the
		 * ability to add, replace, or remove.
		 * @param settingsConsumer a {@link Consumer} of the configuration settings
		 * {@code Map}
		 * @return the {@link AbstractBuilder} for further configuration
		 */
		public B settings(Consumer<Map<String, Object>> settingsConsumer) {
			settingsConsumer.accept(getSettings());
			return getThis();
		}

		public abstract T build();

		protected final Map<String, Object> getSettings() {
			return this.settings;
		}

		@SuppressWarnings("unchecked")
		protected final B getThis() {
			return (B) this;
		}

	}

}
