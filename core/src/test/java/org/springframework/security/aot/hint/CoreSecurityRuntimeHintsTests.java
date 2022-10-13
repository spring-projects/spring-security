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

import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link CoreSecurityRuntimeHints}
 *
 * @author Marcus Da Coregio
 */
class CoreSecurityRuntimeHintsTests {

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

	@ParameterizedTest
	@MethodSource("getAuthenticationEvents")
	void exceptionEventsHasHints(Class<? extends AbstractAuthenticationEvent> event) {
		assertThat(RuntimeHintsPredicates.reflection().onType(event)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Test
	void methodSecurityExpressionRootHasHints() {
		assertThat(RuntimeHintsPredicates.reflection()
				.onType(TypeReference
						.of("org.springframework.security.access.expression.method.MethodSecurityExpressionRoot"))
				.withMemberCategories(MemberCategory.INVOKE_PUBLIC_METHODS)).accepts(this.hints);
	}

	@Test
	void abstractAuthenticationTokenHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(AbstractAuthenticationToken.class)
				.withMemberCategories(MemberCategory.INVOKE_PUBLIC_METHODS)).accepts(this.hints);
	}

	private static Stream<Class<? extends AbstractAuthenticationEvent>> getAuthenticationEvents() {
		return Stream.of(AuthenticationFailureBadCredentialsEvent.class,
				AuthenticationFailureCredentialsExpiredEvent.class, AuthenticationFailureDisabledEvent.class,
				AuthenticationFailureExpiredEvent.class, AuthenticationFailureLockedEvent.class,
				AuthenticationFailureProviderNotFoundEvent.class, AuthenticationFailureProxyUntrustedEvent.class,
				AuthenticationFailureServiceExceptionEvent.class);
	}

	@ParameterizedTest
	@MethodSource("getAuthenticationExceptions")
	void exceptionHasHints(Class<? extends AuthenticationException> exception) {
		assertThat(RuntimeHintsPredicates.reflection().onType(exception)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	private static Stream<Class<? extends AuthenticationException>> getAuthenticationExceptions() {
		return Stream.of(AuthenticationServiceException.class, AccountExpiredException.class,
				BadCredentialsException.class, CredentialsExpiredException.class, DisabledException.class,
				LockedException.class, UsernameNotFoundException.class, ProviderNotFoundException.class);
	}

	@Test
	void defaultJdbcSchemaFileHasHints() {
		assertThat(RuntimeHintsPredicates.resource()
				.forResource("org/springframework/security/core/userdetails/jdbc/users.ddl")).accepts(this.hints);
	}

	@Test
	void securityContextHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(SecurityContextImpl.class)
				.withMemberCategories(MemberCategory.INVOKE_PUBLIC_METHODS)).accepts(this.hints);
	}

}
