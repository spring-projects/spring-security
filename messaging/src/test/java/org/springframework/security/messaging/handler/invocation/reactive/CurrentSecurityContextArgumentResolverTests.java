/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.messaging.handler.invocation.reactive;

import org.junit.Test;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.SynthesizingMethodParameter;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.messaging.handler.invocation.ResolvableMethod;
import reactor.core.publisher.Mono;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class CurrentSecurityContextArgumentResolverTests {
	private CurrentSecurityContextArgumentResolver resolver = new CurrentSecurityContextArgumentResolver();

	@Test
	public void supportsParameterWhenAuthenticationPrincipalThenTrue() {
		assertThat(this.resolver.supportsParameter(arg0("currentSecurityContextOnMonoSecurityContext"))).isTrue();
	}

	@Test
	public void resolveArgumentWhenAuthenticationPrincipalAndEmptyContextThenNull() {
		Object result = this.resolver.resolveArgument(arg0("currentSecurityContextOnMonoSecurityContext"), null).block();
		assertThat(result).isNull();
	}

	@Test
	public void resolveArgumentWhenAuthenticationPrincipalThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		Mono<SecurityContext> result = (Mono<SecurityContext>) this.resolver.resolveArgument(arg0("currentSecurityContextOnMonoSecurityContext"), null)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		assertThat(result.block().getAuthentication()).isEqualTo(authentication);
	}

	@SuppressWarnings("unused")
	private void currentSecurityContextOnMonoSecurityContext(@CurrentSecurityContext Mono<SecurityContext> context) {
	}

	@Test
	public void supportsParameterWhenCurrentUserThenTrue() {
		assertThat(this.resolver.supportsParameter(arg0("currentUserOnMonoUserDetails"))).isTrue();
	}

	@Test
	public void resolveArgumentWhenMonoAndAuthenticationPrincipalThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		Mono<UserDetails> result = (Mono<UserDetails>) this.resolver.resolveArgument(arg0("currentUserOnMonoUserDetails"), null)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		assertThat(result.block()).isEqualTo(authentication.getPrincipal());
	}

	@SuppressWarnings("unused")
	private void currentUserOnMonoUserDetails(@CurrentUser Mono<UserDetails> user) {
	}

	@Test
	public void resolveArgumentWhenExpressionThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		Mono<String> result = (Mono<String>) this.resolver.resolveArgument(arg0("authenticationPrincipalExpression"), null)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		assertThat(result.block()).isEqualTo(authentication.getName());
	}

	@SuppressWarnings("unused")
	private void authenticationPrincipalExpression(@CurrentSecurityContext(expression = "authentication?.principal?.username") Mono<String> username) {
	}

	@Test
	public void supportsParameterWhenNotAnnotatedThenFalse() {
		assertThat(this.resolver.supportsParameter(arg0("monoUserDetails"))).isFalse();
	}

	@SuppressWarnings("unused")
	private void monoUserDetails(Mono<UserDetails> user) {
	}

	private MethodParameter arg0(String methodName) {
		ResolvableMethod method = ResolvableMethod.on(getClass()).named(methodName).method();
		return new SynthesizingMethodParameter(method.method(), 0);
	}

	@CurrentSecurityContext(expression = "authentication?.principal")
	@Retention(RetentionPolicy.RUNTIME)
	@interface CurrentUser {}
}
