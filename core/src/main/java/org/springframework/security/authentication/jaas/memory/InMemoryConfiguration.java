/*
 * Copyright 2010-2016 the original author or authors.
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

package org.springframework.security.authentication.jaas.memory;

import java.util.Collections;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.springframework.util.Assert;

/**
 * <p>
 * An in memory representation of a JAAS configuration. The constructor accepts a Map
 * where the key represents the name of the login context name and the value is an Array
 * of {@link AppConfigurationEntry} for that login context name. A default Array of
 * {@link AppConfigurationEntry}s can be specified which will be returned if a login
 * context is specified which is undefined.
 * </p>
 *
 * @author Rob Winch
 */
public class InMemoryConfiguration extends Configuration {

	private final AppConfigurationEntry[] defaultConfiguration;

	private final Map<String, AppConfigurationEntry[]> mappedConfigurations;

	/**
	 * Creates a new instance with only a defaultConfiguration. Any configuration name
	 * will result in defaultConfiguration being returned.
	 * @param defaultConfiguration The result for any calls to
	 * {@link #getAppConfigurationEntry(String)}. Can be <code>null</code>.
	 */
	public InMemoryConfiguration(AppConfigurationEntry[] defaultConfiguration) {
		this(Collections.<String, AppConfigurationEntry[]>emptyMap(), defaultConfiguration);
	}

	/**
	 * Creates a new instance with a mapping of login context name to an array of
	 * {@link AppConfigurationEntry}s.
	 * @param mappedConfigurations each key represents a login context name and each value
	 * is an Array of {@link AppConfigurationEntry}s that should be used.
	 */
	public InMemoryConfiguration(Map<String, AppConfigurationEntry[]> mappedConfigurations) {
		this(mappedConfigurations, null);
	}

	/**
	 * Creates a new instance with a mapping of login context name to an array of
	 * {@link AppConfigurationEntry}s along with a default configuration that will be used
	 * if no mapping is found for the given login context name.
	 * @param mappedConfigurations each key represents a login context name and each value
	 * is an Array of {@link AppConfigurationEntry}s that should be used.
	 * @param defaultConfiguration The result for any calls to
	 * {@link #getAppConfigurationEntry(String)}. Can be <code>null</code>.
	 */
	public InMemoryConfiguration(Map<String, AppConfigurationEntry[]> mappedConfigurations,
			AppConfigurationEntry[] defaultConfiguration) {
		Assert.notNull(mappedConfigurations, "mappedConfigurations cannot be null.");
		this.mappedConfigurations = mappedConfigurations;
		this.defaultConfiguration = defaultConfiguration;
	}

	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		AppConfigurationEntry[] mappedResult = this.mappedConfigurations.get(name);
		return mappedResult == null ? this.defaultConfiguration : mappedResult;
	}

	/**
	 * Does nothing, but required for JDK5
	 */
	@Override
	public void refresh() {
	}

}
