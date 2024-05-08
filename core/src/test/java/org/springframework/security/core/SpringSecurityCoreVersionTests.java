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

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.core.SpringVersion;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Checks that the embedded version information is up to date.
 *
 * @author Luke Taylor
 * @author Rob Winch
 */
@ExtendWith(MockitoExtension.class)
public class SpringSecurityCoreVersionTests {

	@Mock
	private Log logger;

	@Mock(answer = Answers.CALLS_REAL_METHODS)
	private MockedStatic<SpringVersion> springVersion;

	@Mock(answer = Answers.CALLS_REAL_METHODS)
	private MockedStatic<SpringSecurityCoreVersion> springSecurityCoreVersion;

	@BeforeEach
	public void setup() throws Exception {
		Field logger = ReflectionUtils.findField(SpringSecurityCoreVersion.class, "logger");
		StaticFinalReflectionUtils.setField(logger, this.logger);
	}

	@AfterEach
	public void cleanup() throws Exception {
		System.clearProperty(getDisableChecksProperty());
		Field logger = ReflectionUtils.findField(SpringSecurityCoreVersion.class, "logger");
		StaticFinalReflectionUtils.setField(logger, LogFactory.getLog(SpringSecurityCoreVersion.class));
	}

	@Test
	public void springVersionIsUpToDate() {
		// Property is set by the build script
		String springVersion = System.getProperty("springVersion");
		assertThat(SpringSecurityCoreVersion.MIN_SPRING_VERSION).isEqualTo(springVersion);
	}

	@Test
	public void serialVersionMajorAndMinorVersionMatchBuildVersion() {
		String version = System.getProperty("springSecurityVersion");
		// Strip patch version
		String serialVersion = String.valueOf(SpringSecurityCoreVersion.SERIAL_VERSION_UID).substring(0, 2);
		assertThat(serialVersion.charAt(0)).isEqualTo(version.charAt(0));
		assertThat(serialVersion.charAt(1)).isEqualTo(version.charAt(2));
	}

	// SEC-2295
	@Test
	public void noLoggingIfVersionsAreEqual() throws Exception {
		String version = "1";
		expectSpringSecurityVersionThenReturn(version);
		expectSpringVersionThenReturn(version);
		performChecks();
		verifyNoMoreInteractions(this.logger);
	}

	@Test
	public void noLoggingIfSpringVersionNull() throws Exception {
		String version = "1";
		expectSpringSecurityVersionThenReturn(version);
		expectSpringVersionThenReturn(null);
		performChecks();
		verifyNoMoreInteractions(this.logger);
	}

	@Test
	public void warnIfSpringVersionTooSmall() throws Exception {
		expectSpringSecurityVersionThenReturn("3");
		expectSpringVersionThenReturn("2");
		performChecks();
		verify(this.logger, times(1)).warn(any());
	}

	@Test
	public void noWarnIfSpringVersionLarger() throws Exception {
		String version = "4.0.0.RELEASE";
		expectSpringSecurityVersionThenReturn(version);
		expectSpringVersionThenReturn(version);
		performChecks();
		verify(this.logger, never()).warn(any());
	}

	// SEC-2697
	@Test
	public void noWarnIfSpringPatchVersionDoubleDigits() throws Exception {
		String minSpringVersion = "3.2.8.RELEASE";
		expectSpringSecurityVersionThenReturn("3.2.0.RELEASE");
		expectSpringVersionThenReturn("3.2.10.RELEASE");
		performChecks(minSpringVersion);
		verify(this.logger, never()).warn(any());
	}

	@Test
	public void noLoggingIfPropertySet() throws Exception {
		expectSpringSecurityVersionThenReturn("3");
		expectSpringVersionThenReturn("2");
		System.setProperty(getDisableChecksProperty(), Boolean.TRUE.toString());
		performChecks();
		verifyNoMoreInteractions(this.logger);
	}

	private String getDisableChecksProperty() {
		return SpringSecurityCoreVersion.class.getName().concat(".DISABLE_CHECKS");
	}

	private void performChecks() {
		Method method = ReflectionUtils.findMethod(SpringSecurityCoreVersion.class, "performVersionChecks");
		ReflectionUtils.makeAccessible(method);
		ReflectionUtils.invokeMethod(method, null);
	}

	private void performChecks(String minSpringVersion) {
		Method method = ReflectionUtils.findMethod(SpringSecurityCoreVersion.class, "performVersionChecks",
				String.class);
		ReflectionUtils.makeAccessible(method);
		ReflectionUtils.invokeMethod(method, null, minSpringVersion);
	}

	private void expectSpringSecurityVersionThenReturn(String version) {
		this.springSecurityCoreVersion.when(SpringSecurityCoreVersion::getVersion).thenReturn(version);
	}

	private void expectSpringVersionThenReturn(String version) {
		this.springVersion.when(SpringVersion::getVersion).thenReturn(version);
	}

}
