/*
 * Copyright 2010-2013 the original author or authors.
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

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.jaas.TestLoginModule;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link InMemoryConfiguration}.
 *
 * @author Rob Winch
 */
public class InMemoryConfigurationTests {

	private AppConfigurationEntry[] defaultEntries;

	private Map<String, AppConfigurationEntry[]> mappedEntries;

	@BeforeEach
	public void setUp() {
		this.defaultEntries = new AppConfigurationEntry[] { new AppConfigurationEntry(TestLoginModule.class.getName(),
				LoginModuleControlFlag.REQUIRED, Collections.<String, Object>emptyMap()) };
		this.mappedEntries = Collections.<String, AppConfigurationEntry[]>singletonMap("name",
				new AppConfigurationEntry[] { new AppConfigurationEntry(TestLoginModule.class.getName(),
						LoginModuleControlFlag.OPTIONAL, Collections.<String, Object>emptyMap()) });
	}

	@Test
	public void constructorNullDefault() {
		assertThat(new InMemoryConfiguration((AppConfigurationEntry[]) null).getAppConfigurationEntry("name")).isNull();
	}

	@Test
	public void constructorNullMapped() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new InMemoryConfiguration((Map<String, AppConfigurationEntry[]>) null));
	}

	@Test
	public void constructorEmptyMap() {
		assertThat(new InMemoryConfiguration(Collections.<String, AppConfigurationEntry[]>emptyMap())
				.getAppConfigurationEntry("name")).isNull();
	}

	@Test
	public void constructorEmptyMapNullDefault() {
		assertThat(new InMemoryConfiguration(Collections.<String, AppConfigurationEntry[]>emptyMap(), null)
				.getAppConfigurationEntry("name")).isNull();
	}

	@Test
	public void constructorNullMapNullDefault() {
		assertThatIllegalArgumentException().isThrownBy(() -> new InMemoryConfiguration(null, null));
	}

	@Test
	public void nonnullDefault() {
		InMemoryConfiguration configuration = new InMemoryConfiguration(this.defaultEntries);
		assertThat(configuration.getAppConfigurationEntry("name")).isEqualTo(this.defaultEntries);
	}

	@Test
	public void mappedNonnullDefault() {
		InMemoryConfiguration configuration = new InMemoryConfiguration(this.mappedEntries, this.defaultEntries);
		assertThat(this.defaultEntries).isEqualTo(configuration.getAppConfigurationEntry("missing"));
		assertThat(this.mappedEntries.get("name")).isEqualTo(configuration.getAppConfigurationEntry("name"));
	}

	@Test
	public void jdk5Compatable() throws Exception {
		Method method = InMemoryConfiguration.class.getDeclaredMethod("refresh");
		assertThat(method.getDeclaringClass()).isEqualTo(InMemoryConfiguration.class);
	}

}
