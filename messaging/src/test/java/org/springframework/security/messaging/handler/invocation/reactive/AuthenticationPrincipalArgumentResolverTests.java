/*
 * Copyright 2002-2024 the original author or authors.
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

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.annotation.AnnotatedMethod;
import org.springframework.core.annotation.SynthesizingMethodParameter;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
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

	@Test
	public void resolveArgumentWhenAliasForOnInterfaceThenInherits() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		Authentication authentication = new TestingAuthenticationToken(principal, "password", "ROLE_USER");
		ResolvableMethod method = ResolvableMethod.on(TestController.class)
			.named("showUserNoConcreteAnnotation")
			.method();
		MethodParameter parameter = new AnnotatedMethod(method.method()).getMethodParameters()[0];
		Mono<Object> result = this.resolver.resolveArgument(parameter, null)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(authentication));
		assertThat(result.block()).isEqualTo(principal.property);
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

	@Test
	public void resolveArgumentCustomMetaAnnotation() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		Mono<Object> result = this.resolver.resolveArgument(arg0("showUserCustomMetaAnnotation"), null)
			.contextWrite(ReactiveSecurityContextHolder
				.withAuthentication(new TestingAuthenticationToken(principal, "password", "ROLE_USER")));
		assertThat(result.block()).isEqualTo(principal.id);
	}

	@Test
	public void resolveArgumentCustomMetaAnnotationTpl() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		this.resolver.setTemplateDefaults(new AnnotationTemplateExpressionDefaults());
		Mono<Object> result = this.resolver.resolveArgument(arg0("showUserCustomMetaAnnotationTpl"), null)
			.contextWrite(ReactiveSecurityContextHolder
				.withAuthentication(new TestingAuthenticationToken(principal, "password", "ROLE_USER")));
		assertThat(result.block()).isEqualTo(principal.id);
	}

	public void showUserCustomMetaAnnotation(@CurrentUser2(expression = "principal.id") int userId) {
	}

	public void showUserCustomMetaAnnotationTpl(@CurrentUser3(property = "id") int userId) {
	}

	static class CustomUserPrincipal {

		public final int id = 1;

		public final String property = "property";

		public Object getPrincipal() {
			return this;
		}

	}

	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal
	public @interface CurrentUser2 {

		@AliasFor(annotation = AuthenticationPrincipal.class)
		String expression() default "";

	}

	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal(expression = "principal.{property}")
	public @interface CurrentUser3 {

		String property() default "";

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@AuthenticationPrincipal
	@interface Property {

		@AliasFor(attribute = "expression", annotation = AuthenticationPrincipal.class)
		String value() default "id";

	}

	private interface TestInterface {

		void showUserNoConcreteAnnotation(@Property("property") String property);

	}

	private static class TestController implements TestInterface {

		@Override
		public void showUserNoConcreteAnnotation(String user) {

		}

	}

}
