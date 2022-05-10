/*
 * Copyright 2019-2021 the original author or authors.
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

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.SynthesizingMethodParameter;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.messaging.handler.invocation.ResolvableMethod;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 */
public class AuthenticationPrincipalArgumentResolverTests {

	private AuthenticationPrincipalArgumentResolver resolver = new AuthenticationPrincipalArgumentResolver();

	@Test
	public void supportsParameterWhenAuthenticationPrincipalThenTrue() {
		assertThat(this.resolver.supportsParameter(arg0("authenticationPrincipalOnMonoUserDetails"))).isTrue();
	}

	@Test
	public void resolveArgumentWhenAuthenticationPrincipalAndEmptyContextThenNull() {
		Object result = this.resolver.resolveArgument(arg0("authenticationPrincipalOnMonoUserDetails"), null).block();
		assertThat(result).isNull();
	}

	@Test
	public void resolveArgumentWhenAuthenticationPrincipalThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		// @formatter:off
		Mono<UserDetails> result = (Mono<UserDetails>) this.resolver
				.resolveArgument(arg0("authenticationPrincipalOnMonoUserDetails"), null)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		// @formatter:on
		assertThat(result.block()).isEqualTo(authentication.getPrincipal());
	}

	@SuppressWarnings("unused")
	private void authenticationPrincipalOnMonoUserDetails(@AuthenticationPrincipal Mono<UserDetails> user) {
	}

	@Test
	public void supportsParameterWhenCurrentUserThenTrue() {
		assertThat(this.resolver.supportsParameter(arg0("currentUserOnMonoUserDetails"))).isTrue();
	}

	@Test
	public void resolveArgumentWhenMonoAndAuthenticationPrincipalThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		// @formatter:off
		Mono<UserDetails> result = (Mono<UserDetails>) this.resolver
				.resolveArgument(arg0("currentUserOnMonoUserDetails"), null)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		// @formatter:on
		assertThat(result.block()).isEqualTo(authentication.getPrincipal());
	}

	@SuppressWarnings("unused")
	private void currentUserOnMonoUserDetails(@CurrentUser Mono<UserDetails> user) {
	}

	@Test
	public void resolveArgumentWhenExpressionThenFound() {
		Authentication authentication = TestAuthentication.authenticatedUser();
		// @formatter:off
		Mono<String> result = (Mono<String>) this.resolver
				.resolveArgument(arg0("authenticationPrincipalExpression"), null)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication))
				.block();
		// @formatter:on
		assertThat(result.block()).isEqualTo(authentication.getName());
	}

	@SuppressWarnings("unused")
	private void authenticationPrincipalExpression(
			@AuthenticationPrincipal(expression = "username") Mono<String> username) {
	}

	@Test
	public void resolveArgumentWhenExpressionPrimitiveThenFound() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		// @formatter:off
		Mono<Object> result = this.resolver
				.resolveArgument(arg0("authenticationPrincipalExpressionPrimitive"), null)
				.contextWrite(ReactiveSecurityContextHolder.withAuthentication(new TestingAuthenticationToken(principal, "password", "ROLE_USER")));
		// @formatter:on
		assertThat(result.block()).isEqualTo(principal.id);
	}

	@SuppressWarnings("unused")
	private void authenticationPrincipalExpressionPrimitive(@AuthenticationPrincipal(expression = "id") int username) {
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

	@AuthenticationPrincipal
	@Retention(RetentionPolicy.RUNTIME)
	@interface CurrentUser {

	}

	static class CustomUserPrincipal {

		public final int id = 1;

	}

}
