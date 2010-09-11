/*
 * Copyright 2010 the original author or authors.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

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
        defaultEntries = new AppConfigurationEntry[] { new AppConfigurationEntry(TestLoginModule.class.getName(),
                LoginModuleControlFlag.REQUIRED, Collections.<String, Object> emptyMap()) };

        mappedEntries = Collections.<String, AppConfigurationEntry[]> singletonMap("name",
                new AppConfigurationEntry[] { new AppConfigurationEntry(TestLoginModule.class.getName(),
                        LoginModuleControlFlag.OPTIONAL, Collections.<String, Object> emptyMap()) });
    }

    @Test
    public void constructorNullDefault() {
        assertNull(new InMemoryConfiguration((AppConfigurationEntry[]) null).getAppConfigurationEntry("name"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullMapped() {
        new InMemoryConfiguration((Map<String, AppConfigurationEntry[]>) null);
    }

    @Test
    public void constructorEmptyMap() {
        assertNull(new InMemoryConfiguration(Collections.<String, AppConfigurationEntry[]> emptyMap())
        .getAppConfigurationEntry("name"));
    }

    @Test
    public void constructorEmptyMapNullDefault() {
        assertNull(new InMemoryConfiguration(Collections.<String, AppConfigurationEntry[]> emptyMap(), null)
        .getAppConfigurationEntry("name"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullMapNullDefault() {
        new InMemoryConfiguration(null, null);
    }

    @Test
    public void nonnullDefault() {
        InMemoryConfiguration configuration = new InMemoryConfiguration(defaultEntries);
        assertArrayEquals(defaultEntries, configuration.getAppConfigurationEntry("name"));
    }

    @Test
    public void mappedNonnullDefault() {
        InMemoryConfiguration configuration = new InMemoryConfiguration(mappedEntries, defaultEntries);
        assertArrayEquals(defaultEntries, configuration.getAppConfigurationEntry("missing"));
        assertArrayEquals(mappedEntries.get("name"), configuration.getAppConfigurationEntry("name"));
    }

    @Test
    public void jdk5Compatable() throws Exception {
        Method method = InMemoryConfiguration.class.getDeclaredMethod("refresh");
        assertEquals(InMemoryConfiguration.class, method.getDeclaringClass());
    }
}
