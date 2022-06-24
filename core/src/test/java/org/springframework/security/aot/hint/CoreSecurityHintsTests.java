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

package org.springframework.security.aot.hint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsPredicates;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link CoreSecurityHints}
 *
 * @author Marcus Da Coregio
 */
class CoreSecurityHintsTests {

	private final RuntimeHints hints = new RuntimeHints();

	@BeforeEach
	void setup() {
		SpringFactoriesLoader.forResourceLocation("META-INF/spring/aot.factories").load(RuntimeHintsRegistrar.class)
				.forEach((registrar) -> registrar.registerHints(this.hints, ClassUtils.getDefaultClassLoader()));
	}

	@Test
	void springSecurityMessagesBundleHasHints() {
		assertThat(RuntimeHintsPredicates.resource().forBundle("org.springframework.security.messages"))
				.accepts(this.hints);
	}

	@Test
	void securityExpressionOperationsHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(SecurityExpressionOperations.class)
				.withMemberCategories(MemberCategory.DECLARED_FIELDS, MemberCategory.INVOKE_DECLARED_METHODS))
						.accepts(this.hints);
	}

	@Test
	void securityExpressionRootHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(SecurityExpressionRoot.class)
				.withMemberCategories(MemberCategory.DECLARED_FIELDS, MemberCategory.INVOKE_DECLARED_METHODS))
						.accepts(this.hints);
	}

	@Test
	void authenticationFailureBadCredentialsEventHasHints() {
		assertExceptionEvent(AuthenticationFailureBadCredentialsEvent.class);
	}

	@Test
	void authenticationFailureCredentialsExpiredEventHasHints() {
		assertExceptionEvent(AuthenticationFailureCredentialsExpiredEvent.class);
	}

	@Test
	void authenticationFailureDisabledEventHasHints() {
		assertExceptionEvent(AuthenticationFailureDisabledEvent.class);
	}

	@Test
	void authenticationFailureExpiredEventHasHints() {
		assertExceptionEvent(AuthenticationFailureExpiredEvent.class);
	}

	@Test
	void authenticationFailureLockedEventHasHints() {
		assertExceptionEvent(AuthenticationFailureLockedEvent.class);
	}

	@Test
	void authenticationFailureProviderNotFoundEventHasHints() {
		assertExceptionEvent(AuthenticationFailureProviderNotFoundEvent.class);
	}

	@Test
	void authenticationFailureProxyUntrustedEventHasHints() {
		assertExceptionEvent(AuthenticationFailureProxyUntrustedEvent.class);
	}

	@Test
	void authenticationFailureServiceExceptionEventHasHints() {
		assertExceptionEvent(AuthenticationFailureServiceExceptionEvent.class);
	}

	@Test
	void authenticationServiceExceptionHasHints() {
		assertExceptionEvent(AuthenticationServiceException.class);
	}

	@Test
	void accountExpiredExceptionHasHints() {
		assertExceptionEvent(AccountExpiredException.class);
	}

	@Test
	void badCredentialsExceptionHasHints() {
		assertExceptionEvent(BadCredentialsException.class);
	}

	@Test
	void credentialsExpiredExceptionHasHints() {
		assertExceptionEvent(CredentialsExpiredException.class);
	}

	@Test
	void disabledExceptionHasHints() {
		assertExceptionEvent(DisabledException.class);
	}

	@Test
	void lockedExceptionHasHints() {
		assertExceptionEvent(LockedException.class);
	}

	@Test
	void usernameNotFoundExceptionHasHints() {
		assertExceptionEvent(UsernameNotFoundException.class);
	}

	@Test
	void providerNotFoundExceptionHasHints() {
		assertExceptionEvent(ProviderNotFoundException.class);
	}

	private void assertExceptionEvent(Class<?> clazz) {
		assertThat(RuntimeHintsPredicates.reflection().onType(clazz)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

}
