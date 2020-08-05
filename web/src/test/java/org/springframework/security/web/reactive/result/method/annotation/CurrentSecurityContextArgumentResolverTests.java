/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.web.reactive.result.method.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.expression.BeanResolver;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.method.ResolvableMethod;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Dan Zheng
 * @since 5.2
 */
@RunWith(MockitoJUnitRunner.class)
public class CurrentSecurityContextArgumentResolverTests {

	@Mock
	ServerWebExchange exchange;

	@Mock
	BindingContext bindingContext;

	@Mock
	Authentication authentication;

	@Mock
	BeanResolver beanResolver;

	@Mock
	SecurityContext securityContext;

	ResolvableMethod securityContextMethod = ResolvableMethod.on(getClass()).named("securityContext").build();

	ResolvableMethod securityContextWithAuthentication = ResolvableMethod.on(getClass())
			.named("securityContextWithAuthentication").build();

	CurrentSecurityContextArgumentResolver resolver;

	@Before
	public void setup() {
		this.resolver = new CurrentSecurityContextArgumentResolver(new ReactiveAdapterRegistry());
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@Test
	public void supportsParameterCurrentSecurityContext() {
		assertThat(this.resolver.supportsParameter(this.securityContextMethod.arg(Mono.class, SecurityContext.class)))
				.isTrue();
	}

	@Test
	public void supportsParameterWithAuthentication() {
		assertThat(this.resolver
				.supportsParameter(this.securityContextWithAuthentication.arg(Mono.class, Authentication.class)))
						.isTrue();
	}

	@Test
	public void resolveArgumentWithNullSecurityContext() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class,
				SecurityContext.class);
		Context context = ReactiveSecurityContextHolder.withSecurityContext(Mono.empty());
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Object obj = argument.subscriberContext(context).block();
		assertThat(obj).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithSecurityContext() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class,
				SecurityContext.class);
		Authentication auth = buildAuthenticationWithPrincipal("hello");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block()
				.block();
		assertThat(securityContext.getAuthentication()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithCustomSecurityContext() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("customSecurityContext").build()
				.arg(Mono.class, SecurityContext.class);
		Authentication auth = buildAuthenticationWithPrincipal("hello");
		Context context = ReactiveSecurityContextHolder.withSecurityContext(Mono.just(new CustomSecurityContext(auth)));
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		CustomSecurityContext securityContext = (CustomSecurityContext) argument.subscriberContext(context)
				.cast(Mono.class).block().block();
		assertThat(securityContext.getAuthentication()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthentication1() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class,
				SecurityContext.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block()
				.block();
		assertThat(securityContext.getAuthentication()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthentication2() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithAuthentication").build()
				.arg(Mono.class, Authentication.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<Object> r = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(r.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithAuthentication1() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithAuthentication").build()
				.arg(Mono.class, Authentication.class);
		Authentication auth = buildAuthenticationWithPrincipal("authentication1");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<Authentication> auth1 = (Mono<Authentication>) argument.subscriberContext(context).block();
		assertThat(auth1.block()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthenticationOptional1() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthPropOptional")
				.build().arg(Mono.class, Object.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<Object> obj = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithAuthenticationOptional1() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthPropOptional")
				.build().arg(Mono.class, Object.class);
		Authentication auth = buildAuthenticationWithPrincipal("auth_optional");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<Object> obj = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isEqualTo("auth_optional");
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullDepthProp1() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthProp").build()
				.arg(Mono.class, Object.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		assertThatExceptionOfType(SpelEvaluationException.class)
				.isThrownBy(() -> argument.subscriberContext(context).block());
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithStringDepthProp() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthStringProp").build()
				.arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("auth_string");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isEqualTo("auth_string");
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeImplicit() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenImplicit").build()
				.arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("invalid_type_implicit");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentErrorOnInvalidTypeWhenExplicitFalse() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitFalse").build()
				.arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("error_on_invalid_type_explicit_false");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentErrorOnInvalidTypeWhenExplicitTrue() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitTrue").build()
				.arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("error_on_invalid_type_explicit_true");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		assertThatExceptionOfType(ClassCastException.class)
				.isThrownBy(() -> argument.subscriberContext(context).block());
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void metaAnnotationWhenDefaultSecurityContextThenInjectSecurityContext() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("currentCustomSecurityContext").build()
				.arg(Mono.class, SecurityContext.class);
		Authentication auth = buildAuthenticationWithPrincipal("current_custom_security_context");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block()
				.block();
		assertThat(securityContext.getAuthentication()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void metaAnnotationWhenCurrentAuthenticationThenInjectAuthentication() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("currentAuthentication").build()
				.arg(Mono.class, Authentication.class);
		Authentication auth = buildAuthenticationWithPrincipal("current_authentication");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		Authentication authentication = (Authentication) argument.subscriberContext(context).cast(Mono.class).block()
				.block();
		assertThat(authentication).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void metaAnnotationWhenCurrentSecurityWithErrorOnInvalidTypeThenInjectSecurityContext() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("currentSecurityWithErrorOnInvalidType")
				.build().arg(Mono.class, SecurityContext.class);
		Authentication auth = buildAuthenticationWithPrincipal("current_security_with_error_on_invalid_type");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block()
				.block();
		assertThat(securityContext.getAuthentication()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void metaAnnotationWhenCurrentSecurityWithErrorOnInvalidTypeThenMisMatch() {
		MethodParameter parameter = ResolvableMethod.on(getClass())
				.named("currentSecurityWithErrorOnInvalidTypeMisMatch").build().arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("current_security_with_error_on_invalid_type_mismatch");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		assertThatExceptionOfType(ClassCastException.class)
				.isThrownBy(() -> argument.subscriberContext(context).cast(Mono.class).block().block());
		ReactiveSecurityContextHolder.clearContext();
	}

	void securityContext(@CurrentSecurityContext Mono<SecurityContext> monoSecurityContext) {
	}

	void customSecurityContext(@CurrentSecurityContext Mono<SecurityContext> monoSecurityContext) {
	}

	void securityContextWithAuthentication(
			@CurrentSecurityContext(expression = "authentication") Mono<Authentication> authentication) {
	}

	void securityContextWithDepthPropOptional(
			@CurrentSecurityContext(expression = "authentication?.principal") Mono<Object> principal) {
	}

	void securityContextWithDepthProp(
			@CurrentSecurityContext(expression = "authentication.principal") Mono<Object> principal) {
	}

	void securityContextWithDepthStringProp(
			@CurrentSecurityContext(expression = "authentication.principal") Mono<String> principal) {
	}

	void errorOnInvalidTypeWhenImplicit(@CurrentSecurityContext Mono<String> implicit) {
	}

	void errorOnInvalidTypeWhenExplicitFalse(
			@CurrentSecurityContext(errorOnInvalidType = false) Mono<String> implicit) {
	}

	void errorOnInvalidTypeWhenExplicitTrue(@CurrentSecurityContext(errorOnInvalidType = true) Mono<String> implicit) {
	}

	void currentCustomSecurityContext(@CurrentCustomSecurityContext Mono<SecurityContext> monoSecurityContext) {
	}

	void currentAuthentication(@CurrentAuthentication Mono<Authentication> authentication) {
	}

	void currentSecurityWithErrorOnInvalidType(
			@CurrentSecurityWithErrorOnInvalidType Mono<SecurityContext> monoSecurityContext) {
	}

	void currentSecurityWithErrorOnInvalidTypeMisMatch(
			@CurrentSecurityWithErrorOnInvalidType Mono<String> typeMisMatch) {
	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext
	@interface CurrentCustomSecurityContext {

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(expression = "authentication")
	@interface CurrentAuthentication {

	}

	@Target({ ElementType.PARAMETER })
	@Retention(RetentionPolicy.RUNTIME)
	@CurrentSecurityContext(errorOnInvalidType = true)
	@interface CurrentSecurityWithErrorOnInvalidType {

	}

	static class CustomSecurityContext implements SecurityContext {

		private Authentication authentication;

		CustomSecurityContext(Authentication authentication) {
			this.authentication = authentication;
		}

		@Override
		public Authentication getAuthentication() {
			return authentication;
		}

		@Override
		public void setAuthentication(Authentication authentication) {
			this.authentication = authentication;
		}

	}

	private Authentication buildAuthenticationWithPrincipal(Object principal) {
		return new TestingAuthenticationToken(principal, "password", "ROLE_USER");
	}

}
