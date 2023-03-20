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

import java.util.List;
import java.util.stream.Stream;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.aot.hint.TypeReference;
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
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureCredentialsExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureDisabledEvent;
import org.springframework.security.authentication.event.AuthenticationFailureExpiredEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProviderNotFoundEvent;
import org.springframework.security.authentication.event.AuthenticationFailureProxyUntrustedEvent;
import org.springframework.security.authentication.event.AuthenticationFailureServiceExceptionEvent;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;

/**
 * {@link RuntimeHintsRegistrar} for core classes
 *
 * @author Marcus Da Coregio
 * @since 6.0
 */
class CoreSecurityRuntimeHints implements RuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		registerExceptionEventsHints(hints);
		registerExpressionEvaluationHints(hints);
		registerMethodSecurityHints(hints);
		hints.resources().registerResourceBundle("org.springframework.security.messages");
		registerDefaultJdbcSchemaFileHint(hints);
		registerSecurityContextHints(hints);
	}

	private void registerMethodSecurityHints(RuntimeHints hints) {
		hints.reflection().registerType(
				TypeReference.of("org.springframework.security.access.expression.method.MethodSecurityExpressionRoot"),
				(builder) -> builder.withMembers(MemberCategory.INVOKE_PUBLIC_METHODS));
		hints.reflection().registerType(AbstractAuthenticationToken.class,
				(builder) -> builder.withMembers(MemberCategory.INVOKE_PUBLIC_METHODS));
	}

	private void registerExpressionEvaluationHints(RuntimeHints hints) {
		hints.reflection().registerTypes(
				List.of(TypeReference.of(SecurityExpressionOperations.class),
						TypeReference.of(SecurityExpressionRoot.class)),
				(builder) -> builder.withMembers(MemberCategory.DECLARED_FIELDS,
						MemberCategory.INVOKE_DECLARED_METHODS));
	}

	private void registerExceptionEventsHints(RuntimeHints hints) {
		hints.reflection().registerTypes(getDefaultAuthenticationExceptionEventPublisherTypes(),
				(builder) -> builder.withMembers(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS));
	}

	private List<TypeReference> getDefaultAuthenticationExceptionEventPublisherTypes() {
		return Stream.of(AuthenticationFailureBadCredentialsEvent.class,
				AuthenticationFailureCredentialsExpiredEvent.class, AuthenticationFailureDisabledEvent.class,
				AuthenticationFailureExpiredEvent.class, AuthenticationFailureLockedEvent.class,
				AuthenticationFailureProviderNotFoundEvent.class, AuthenticationFailureProxyUntrustedEvent.class,
				AuthenticationFailureServiceExceptionEvent.class, AuthenticationServiceException.class,
				AccountExpiredException.class, BadCredentialsException.class, CredentialsExpiredException.class,
				DisabledException.class, LockedException.class, UsernameNotFoundException.class,
				ProviderNotFoundException.class).map(TypeReference::of).toList();
	}

	private void registerDefaultJdbcSchemaFileHint(RuntimeHints hints) {
		hints.resources().registerPattern(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION);
	}

	private void registerSecurityContextHints(RuntimeHints hints) {
		hints.reflection().registerType(SecurityContextImpl.class,
				(builder) -> builder.withMembers(MemberCategory.INVOKE_PUBLIC_METHODS));
	}

}
