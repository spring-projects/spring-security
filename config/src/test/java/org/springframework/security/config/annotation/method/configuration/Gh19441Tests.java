/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import org.junit.jupiter.api.Test;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.test.support.ClassPathExclusions;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for gh-19441: {@code spring-security-access} moved
 * {@link org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor}
 * out of {@code spring-security-core} and into the optional
 * {@code spring-security-access} module. {@link EnableMethodSecurity} and
 * {@link EnableReactiveMethodSecurity}'s default (AuthorizationManager-based) mode never
 * needed that class and continue to work without {@code spring-security-access} on the
 * classpath, but the deprecated legacy method security annotations do need it and
 * previously failed with a confusing {@link NoClassDefFoundError} instead of an
 * actionable message.
 */
@ClassPathExclusions("spring-security-access-*.jar")
public class Gh19441Tests {

	@Test
	public void enableMethodSecurityWhenAccessModuleAbsentThenContextStartsCleanly() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
			context.register(EnableMethodSecurityConfig.class);
			context.refresh();
		}
	}

	@Test
	public void enableReactiveMethodSecurityWhenAccessModuleAbsentThenContextStartsCleanly() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
			context.register(EnableReactiveMethodSecurityConfig.class);
			context.refresh();
		}
	}

	@Test
	public void enableGlobalMethodSecurityWhenProxyModeAndAccessModuleAbsentThenClearException() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
			context.register(EnableGlobalMethodSecurityProxyConfig.class);
			assertThatExceptionOfType(Exception.class).isThrownBy(context::refresh)
				.havingRootCause()
				.isInstanceOf(IllegalStateException.class)
				.withMessageContaining("spring-security-access");
		}
	}

	@Test
	public void enableGlobalMethodSecurityWhenAspectJModeAndAccessModuleAbsentThenClearException() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
			context.register(EnableGlobalMethodSecurityAspectJConfig.class);
			assertThatExceptionOfType(Exception.class).isThrownBy(context::refresh)
				.havingRootCause()
				.isInstanceOf(IllegalStateException.class)
				.withMessageContaining("spring-security-access");
		}
	}

	@Test
	public void enableReactiveMethodSecurityWhenUseAuthorizationManagerFalseAndAccessModuleAbsentThenClearException() {
		try (AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext()) {
			context.register(EnableReactiveMethodSecurityLegacyConfig.class);
			assertThatExceptionOfType(Exception.class).isThrownBy(context::refresh)
				.havingRootCause()
				.isInstanceOf(IllegalStateException.class)
				.withMessageContaining("spring-security-access");
		}
	}

	@Configuration
	@EnableMethodSecurity
	static class EnableMethodSecurityConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity
	static class EnableReactiveMethodSecurityConfig {

	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class EnableGlobalMethodSecurityProxyConfig {

	}

	@Configuration
	@EnableGlobalMethodSecurity(prePostEnabled = true, mode = AdviceMode.ASPECTJ)
	static class EnableGlobalMethodSecurityAspectJConfig {

	}

	@Configuration
	@EnableReactiveMethodSecurity(useAuthorizationManager = false)
	static class EnableReactiveMethodSecurityLegacyConfig {

	}

}
