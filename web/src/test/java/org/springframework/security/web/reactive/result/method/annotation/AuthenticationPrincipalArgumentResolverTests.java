/*
 * Copyright 2002-2018 the original author or authors.
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.expression.BeanResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.method.ResolvableMethod;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.lang.annotation.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthenticationPrincipalArgumentResolverTests {

	@Mock
	ServerWebExchange exchange;

	@Mock
	BindingContext bindingContext;

	@Mock
	Authentication authentication;

	@Mock
	BeanResolver beanResolver;

	ResolvableMethod authenticationPrincipal = ResolvableMethod.on(getClass()).named("authenticationPrincipal").build();

	ResolvableMethod spel = ResolvableMethod.on(getClass()).named("spel").build();

	ResolvableMethod meta = ResolvableMethod.on(getClass()).named("meta").build();

	ResolvableMethod bean = ResolvableMethod.on(getClass()).named("bean").build();

	AuthenticationPrincipalArgumentResolver resolver;

	@Before
	public void setup() {
		resolver = new AuthenticationPrincipalArgumentResolver(new ReactiveAdapterRegistry());
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@Test
	public void supportsParameterAuthenticationPrincipal() {
		assertThat(resolver.supportsParameter(this.authenticationPrincipal.arg(String.class))).isTrue();
	}

	@Test
	public void supportsParameterCurrentUser() {
		assertThat(resolver.supportsParameter(this.meta.arg(String.class))).isTrue();
	}

	@Test
	public void resolveArgumentWhenIsAuthenticationThenObtainsPrincipal() {
		MethodParameter parameter = this.authenticationPrincipal.arg(String.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isEqualTo(authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenIsEmptyThenMonoEmpty() {
		MethodParameter parameter = this.authenticationPrincipal.arg(String.class);

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);

		assertThat(argument).isNotNull();
		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenMonoIsAuthenticationThenObtainsPrincipal() {
		MethodParameter parameter = this.authenticationPrincipal.arg(Mono.class, String.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.cast(Mono.class).block().block()).isEqualTo(authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenMonoIsAuthenticationAndNoGenericThenObtainsPrincipal() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("authenticationPrincipalNoGeneric").build()
				.arg(Mono.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.cast(Mono.class).block().block()).isEqualTo(authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenSpelThenObtainsPrincipal() {
		MyUser user = new MyUser(3L);
		MethodParameter parameter = this.spel.arg(Long.class);
		when(authentication.getPrincipal()).thenReturn(user);

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isEqualTo(user.getId());
	}

	@Test
	public void resolveArgumentWhenBeanThenObtainsPrincipal() throws Exception {
		MyUser user = new MyUser(3L);
		MethodParameter parameter = this.bean.arg(Long.class);
		when(authentication.getPrincipal()).thenReturn(user);
		when(this.beanResolver.resolve(any(), eq("beanName"))).thenReturn(new Bean());

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isEqualTo(user.getId());
	}

	@Test
	public void resolveArgumentWhenMetaThenObtainsPrincipal() {
		MethodParameter parameter = this.meta.arg(String.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isEqualTo("user");
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeImplicit() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenImplicit").build()
				.arg(Integer.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeExplicitFalse() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitFalse").build()
				.arg(Integer.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeExplicitTrue() {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitTrue").build()
				.arg(Integer.class);
		when(authentication.getPrincipal()).thenReturn("user");

		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange)
				.subscriberContext(ReactiveSecurityContextHolder.withAuthentication(authentication));

		assertThatThrownBy(() -> argument.block()).isInstanceOf(ClassCastException.class);
	}

	void authenticationPrincipal(@AuthenticationPrincipal String principal,
			@AuthenticationPrincipal Mono<String> monoPrincipal) {
	}

	void authenticationPrincipalNoGeneric(@AuthenticationPrincipal Mono monoPrincipal) {
	}

	void spel(@AuthenticationPrincipal(expression = "id") Long id) {
	}

	void bean(@AuthenticationPrincipal(expression = "@beanName.methodName(#this)") Long id) {
	}

	void meta(@CurrentUser String principal) {
	}

	void errorOnInvalidTypeWhenImplicit(@AuthenticationPrincipal Integer implicit) {
	}

	void errorOnInvalidTypeWhenExplicitFalse(@AuthenticationPrincipal(errorOnInvalidType = false) Integer implicit) {
	}

	void errorOnInvalidTypeWhenExplicitTrue(@AuthenticationPrincipal(errorOnInvalidType = true) Integer implicit) {
	}

	static class Bean {

		public Long methodName(MyUser user) {
			return user.getId();
		}

	}

	static class MyUser {

		private final Long id;

		MyUser(Long id) {
			this.id = id;
		}

		public Long getId() {
			return id;
		}

	}

	@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Documented
	@AuthenticationPrincipal
	public @interface CurrentUser {

	}

}
