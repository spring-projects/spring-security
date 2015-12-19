/*
 * Copyright 2010-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication.jaas.memory;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.jaas.TestLoginModule;

/**
 * Tests {@link InMemoryConfiguration}.
 * 
 * @author Rob Winch
 */
public class InMemoryConfigurationTests {

	private AppConfigurationEntry[] defaultEntries;
	private Map<String, AppConfigurationEntry[]> mappedEntries;

	@Before
	public void setUp() {
		defaultEntries = new AppConfigurationEntry[] { new AppConfigurationEntry(
				TestLoginModule.class.getName(), LoginModuleControlFlag.REQUIRED,
				Collections.<String, Object> emptyMap()) };

		mappedEntries = Collections.<String, AppConfigurationEntry[]> singletonMap(
				"name", new AppConfigurationEntry[] { new AppConfigurationEntry(
						TestLoginModule.class.getName(), LoginModuleControlFlag.OPTIONAL,
						Collections.<String, Object> emptyMap()) });
	}

	@Test
	public void constructorNullDefault() {
		assertThat(new InMemoryConfiguration((AppConfigurationEntry[]) null).getAppConfigurationEntry("name")).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullMapped() {
		new InMemoryConfiguration((Map<String, AppConfigurationEntry[]>) null);
	}

	@Test
	public void constructorEmptyMap() {
		assertThat(new InMemoryConfiguration(
				Collections.<String, AppConfigurationEntry[]> emptyMap())
				.getAppConfigurationEntry("name")).isNull();
	}

	@Test
	public void constructorEmptyMapNullDefault() {
		assertThat(new InMemoryConfiguration(
				Collections.<String, AppConfigurationEntry[]> emptyMap(), null)
				.getAppConfigurationEntry("name")).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullMapNullDefault() {
		new InMemoryConfiguration(null, null);
	}

	@Test
	public void nonnullDefault() {
		InMemoryConfiguration configuration = new InMemoryConfiguration(defaultEntries);
		assertThat(configuration.getAppConfigurationEntry("name")).isEqualTo(defaultEntries);
	}

	@Test
	public void mappedNonnullDefault() {
		InMemoryConfiguration configuration = new InMemoryConfiguration(mappedEntries,
				defaultEntries);
		assertThat(defaultEntries).isEqualTo(configuration.getAppConfigurationEntry("missing"));
		assertThat(mappedEntries.get("name")).isEqualTo(configuration.getAppConfigurationEntry("name"));
	}

	@Test
	public void jdk5Compatable() throws Exception {
		Method method = InMemoryConfiguration.class.getDeclaredMethod("refresh");
		assertThat(method.getDeclaringClass()).isEqualTo(InMemoryConfiguration.class);
	}
}
