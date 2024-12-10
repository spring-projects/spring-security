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

package org.springframework.security.web.reactive.result.method.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.core.MethodParameter;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.core.annotation.AliasFor;
import org.springframework.core.annotation.AnnotatedMethod;
import org.springframework.core.annotation.SynthesizingMethodParameter;
import org.springframework.expression.BeanResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AnnotationTemplateExpressionDefaults;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.web.method.ResolvableMethod;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
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

	ResolvableMethod spelPrimitive = ResolvableMethod.on(getClass()).named("spelPrimitive").build();

	ResolvableMethod meta = ResolvableMethod.on(getClass()).named("meta").build();

	ResolvableMethod bean = ResolvableMethod.on(getClass()).named("bean").build();

	AuthenticationPrincipalArgumentResolver resolver;

	@BeforeEach
	public void setup() {
		this.resolver = new AuthenticationPrincipalArgumentResolver(new ReactiveAdapterRegistry());
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@Test
	public void supportsParameterAuthenticationPrincipal() {
		assertThat(this.resolver.supportsParameter(this.authenticationPrincipal.arg(String.class))).isTrue();
	}

	@Test
	public void supportsParameterCurrentUser() {
		assertThat(this.resolver.supportsParameter(this.meta.arg(String.class))).isTrue();
	}

	@Test
	public void resolveArgumentWhenIsAuthenticationThenObtainsPrincipal() {
		MethodParameter parameter = this.authenticationPrincipal.arg(String.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isEqualTo(this.authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenIsEmptyThenMonoEmpty() {
		MethodParameter parameter = this.authenticationPrincipal.arg(String.class);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange);
		assertThat(argument).isNotNull();
		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenMonoIsAuthenticationThenObtainsPrincipal() {
		MethodParameter parameter = this.authenticationPrincipal.arg(Mono.class, String.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.cast(Mono.class).block().block()).isEqualTo(this.authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenMonoIsAuthenticationAndNoGenericThenObtainsPrincipal() {
		MethodParameter parameter = ResolvableMethod.on(getClass())
			.named("authenticationPrincipalNoGeneric")
			.build()
			.arg(Mono.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.cast(Mono.class).block().block()).isEqualTo(this.authentication.getPrincipal());
	}

	@Test
	public void resolveArgumentWhenSpelThenObtainsPrincipal() {
		MyUser user = new MyUser(3L);
		MethodParameter parameter = this.spel.arg(Long.class);
		given(this.authentication.getPrincipal()).willReturn(user);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isEqualTo(user.getId());
	}

	@Test
	public void resolveArgumentWhenSpelWithPrimitiveThenObtainsPrincipal() {
		MyUserPrimitive user = new MyUserPrimitive(3);
		MethodParameter parameter = this.spelPrimitive.arg(int.class);
		given(this.authentication.getPrincipal()).willReturn(user);
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isEqualTo(user.getId());
	}

	@Test
	public void resolveArgumentWhenBeanThenObtainsPrincipal() throws Exception {
		MyUser user = new MyUser(3L);
		MethodParameter parameter = this.bean.arg(Long.class);
		given(this.authentication.getPrincipal()).willReturn(user);
		given(this.beanResolver.resolve(any(), eq("beanName"))).willReturn(new Bean());
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isEqualTo(user.getId());
	}

	@Test
	public void resolveArgumentWhenMetaThenObtainsPrincipal() {
		MethodParameter parameter = this.meta.arg(String.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isEqualTo("user");
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeImplicit() {
		MethodParameter parameter = ResolvableMethod.on(getClass())
			.named("errorOnInvalidTypeWhenImplicit")
			.build()
			.arg(Integer.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeExplicitFalse() {
		MethodParameter parameter = ResolvableMethod.on(getClass())
			.named("errorOnInvalidTypeWhenExplicitFalse")
			.build()
			.arg(Integer.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(argument.block()).isNull();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeExplicitTrue() {
		MethodParameter parameter = ResolvableMethod.on(getClass())
			.named("errorOnInvalidTypeWhenExplicitTrue")
			.build()
			.arg(Integer.class);
		given(this.authentication.getPrincipal()).willReturn("user");
		Mono<Object> argument = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThatExceptionOfType(ClassCastException.class).isThrownBy(() -> argument.block());
	}

	@Test
	public void resolveArgumentCustomMetaAnnotation() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		given(this.authentication.getPrincipal()).willReturn(principal);
		Mono<Object> result = this.resolver
			.resolveArgument(arg0("showUserCustomMetaAnnotation"), this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(result.block()).isEqualTo(principal.id);
	}

	@Test
	public void resolveArgumentCustomMetaAnnotationTpl() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		given(this.authentication.getPrincipal()).willReturn(principal);
		this.resolver.setTemplateDefaults(new AnnotationTemplateExpressionDefaults());
		Mono<Object> result = this.resolver
			.resolveArgument(arg0("showUserCustomMetaAnnotationTpl"), this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(result.block()).isEqualTo(principal.id);
	}

	@Test
	public void resolveArgumentWhenAliasForOnInterfaceThenInherits() {
		CustomUserPrincipal principal = new CustomUserPrincipal();
		given(this.authentication.getPrincipal()).willReturn(principal);
		ResolvableMethod method = ResolvableMethod.on(TestController.class)
			.named("showUserNoConcreteAnnotation")
			.build();
		MethodParameter parameter = new AnnotatedMethod(method.method()).getMethodParameters()[0];
		Mono<Object> result = this.resolver.resolveArgument(parameter, this.bindingContext, this.exchange)
			.contextWrite(ReactiveSecurityContextHolder.withAuthentication(this.authentication));
		assertThat(result.block()).isEqualTo(principal.property);
	}

	private MethodParameter arg0(String methodName) {
		ResolvableMethod method = ResolvableMethod.on(getClass()).named(methodName).build();
		return new SynthesizingMethodParameter(method.method(), 0);
	}

	public void showUserCustomMetaAnnotation(@CurrentUser2(expression = "principal.id") int userId) {
	}

	public void showUserCustomMetaAnnotationTpl(@CurrentUser3(property = "id") int userId) {
	}

	void authenticationPrincipal(@AuthenticationPrincipal String principal,
			@AuthenticationPrincipal Mono<String> monoPrincipal) {
	}

	void authenticationPrincipalNoGeneric(@AuthenticationPrincipal Mono monoPrincipal) {
	}

	void spel(@AuthenticationPrincipal(expression = "id") Long id) {
	}

	void spelPrimitive(@AuthenticationPrincipal(expression = "id") int id) {
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
			return this.id;
		}

	}

	static class MyUserPrimitive {

		private final int id;

		MyUserPrimitive(int id) {
			this.id = id;
		}

		public int getId() {
			return this.id;
		}

	}

	@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Documented
	@AuthenticationPrincipal
	public @interface CurrentUser {

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
