/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.core;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.powermock.api.mockito.PowerMockito.doReturn;
import static org.powermock.api.mockito.PowerMockito.spy;

import org.apache.commons.logging.Log;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.reflect.Whitebox;
import org.springframework.core.SpringVersion;

/**
 * Checks that the embedded version information is up to date.
 *
 * @author Luke Taylor
 * @author Rob Winch
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ SpringSecurityCoreVersion.class, SpringVersion.class })
public class SpringSecurityCoreVersionTests {

	@Mock
	private Log logger;

	@Before
	public void setup() {
		Whitebox.setInternalState(SpringSecurityCoreVersion.class, logger);
	}

	@After
	public void cleanup() throws Exception {
		System.clearProperty(getDisableChecksProperty());
	}

	@Test
	public void springVersionIsUpToDate() throws Exception {
		// Property is set by the build script
		String springVersion = System.getProperty("springVersion");

		assertThat(SpringSecurityCoreVersion.MIN_SPRING_VERSION).isEqualTo(springVersion);
	}

	@Test
	public void serialVersionMajorAndMinorVersionMatchBuildVersion() throws Exception {
		String version = System.getProperty("springSecurityVersion");

		// Strip patch version
		String serialVersion = String.valueOf(
				SpringSecurityCoreVersion.SERIAL_VERSION_UID).substring(0, 2);

		assertThat(serialVersion.charAt(0)).isEqualTo(version.charAt(0));
		assertThat(serialVersion.charAt(1)).isEqualTo(version.charAt(2));

	}

	// SEC-2295
	@Test
	public void noLoggingIfVersionsAreEqual() throws Exception {
		String version = "1";
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn(version).when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn(version).when(SpringVersion.class, "getVersion");

		performChecks();

		verifyZeroInteractions(logger);
	}

	@Test
	public void noLoggingIfSpringVersionNull() throws Exception {
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn("1").when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn(null).when(SpringVersion.class, "getVersion");

		performChecks();

		verifyZeroInteractions(logger);
	}

	@Test
	public void warnIfSpringVersionTooSmall() throws Exception {
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn("3").when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn("2").when(SpringVersion.class, "getVersion");

		performChecks();

		verify(logger, times(1)).warn(any());
	}

	@Test
	public void noWarnIfSpringVersionLarger() throws Exception {
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn("4.0.0.RELEASE").when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn("4.0.0.RELEASE").when(SpringVersion.class, "getVersion");

		performChecks();

		verify(logger, never()).warn(any());
	}

	// SEC-2697
	@Test
	public void noWarnIfSpringPatchVersionDoubleDigits() throws Exception {
		String minSpringVersion = "3.2.8.RELEASE";
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn("3.2.0.RELEASE").when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn("3.2.10.RELEASE").when(SpringVersion.class, "getVersion");

		performChecks(minSpringVersion);

		verify(logger, never()).warn(any());
	}

	@Test
	public void noLoggingIfPropertySet() throws Exception {
		spy(SpringSecurityCoreVersion.class);
		spy(SpringVersion.class);
		doReturn("3").when(SpringSecurityCoreVersion.class, "getVersion");
		doReturn("2").when(SpringVersion.class, "getVersion");
		System.setProperty(getDisableChecksProperty(), Boolean.TRUE.toString());

		performChecks();

		verifyZeroInteractions(logger);
	}

	private String getDisableChecksProperty() throws Exception {
		return SpringSecurityCoreVersion.class.getName().concat(".DISABLE_CHECKS");
	}

	private void performChecks() throws Exception {
		Whitebox.invokeMethod(SpringSecurityCoreVersion.class, "performVersionChecks");
	}

	private void performChecks(String minSpringVersion) throws Exception {
		Whitebox.invokeMethod(SpringSecurityCoreVersion.class, "performVersionChecks",
				minSpringVersion);
	}
}
