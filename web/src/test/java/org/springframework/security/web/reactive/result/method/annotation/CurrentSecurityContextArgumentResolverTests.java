/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.method.ResolvableMethod;
import org.springframework.web.reactive.BindingContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * @author Dan Zheng
 * @since 5.2.x
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
	ResolvableMethod securityContextWithAuthentication = ResolvableMethod.on(getClass()).named("securityContextWithAuthentication").build();

	CurrentSecurityContextArgumentResolver resolver;

	@Before
	public void setup() {
		resolver =  new CurrentSecurityContextArgumentResolver(new ReactiveAdapterRegistry());
		this.resolver.setBeanResolver(this.beanResolver);
	}

	@Test
	public void supportsParameterCurrentSecurityContext() throws Exception {
		assertThat(resolver.supportsParameter(this.securityContextMethod.arg(Mono.class, SecurityContext.class))).isTrue();
	}

	@Test
	public void supportsParameterWithAuthentication() throws Exception {
		assertThat(resolver.supportsParameter(this.securityContextWithAuthentication.arg(Mono.class, Authentication.class))).isTrue();
	}

	@Test
	public void resolveArgumentWithNullSecurityContext() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class, SecurityContext.class);
		Context context = ReactiveSecurityContextHolder.withSecurityContext(Mono.empty());
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Object obj = argument.subscriberContext(context).block();
		assertThat(obj).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithSecurityContext() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class, SecurityContext.class);
		Authentication auth = buildAuthenticationWithPrincipal("hello");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block().block();
		assertThat(securityContext.getAuthentication()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthentication1() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContext").build().arg(Mono.class, SecurityContext.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		SecurityContext securityContext = (SecurityContext) argument.subscriberContext(context).cast(Mono.class).block().block();
		assertThat(securityContext.getAuthentication()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthentication2() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithAuthentication").build().arg(Mono.class, Authentication.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<Object> r = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(r.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithAuthentication1() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithAuthentication").build().arg(Mono.class, Authentication.class);
		Authentication auth = buildAuthenticationWithPrincipal("authentication1");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<Authentication> auth1 = (Mono<Authentication>) argument.subscriberContext(context).block();
		assertThat(auth1.block()).isSameAs(auth);
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullAuthenticationOptional1() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthPropOptional").build().arg(Mono.class, Object.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<Object> obj = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithAuthenticationOptional1() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthPropOptional").build().arg(Mono.class, Object.class);
		Authentication auth = buildAuthenticationWithPrincipal("auth_optional");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<Object> obj = (Mono<Object>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isEqualTo("auth_optional");
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithNullDepthProp1() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthProp").build().arg(Mono.class, Object.class);
		Authentication auth = null;
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		try {
			Mono<Object> obj = (Mono<Object>) argument.subscriberContext(context).block();
			fail("should not reach here");
		} catch(SpelEvaluationException e) {
		}
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWithStringDepthProp() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("securityContextWithDepthStringProp").build().arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("auth_string");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isEqualTo("auth_string");
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentWhenErrorOnInvalidTypeImplicit() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenImplicit").build().arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("invalid_type_implicit");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentErrorOnInvalidTypeWhenExplicitFalse() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitFalse").build().arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("error_on_invalid_type_explicit_false");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
		assertThat(obj.block()).isNull();
		ReactiveSecurityContextHolder.clearContext();
	}

	@Test
	public void resolveArgumentErrorOnInvalidTypeWhenExplicitTrue() throws Exception {
		MethodParameter parameter = ResolvableMethod.on(getClass()).named("errorOnInvalidTypeWhenExplicitTrue").build().arg(Mono.class, String.class);
		Authentication auth = buildAuthenticationWithPrincipal("error_on_invalid_type_explicit_true");
		Context context = ReactiveSecurityContextHolder.withAuthentication(auth);
		Mono<Object> argument = resolver.resolveArgument(parameter, bindingContext, exchange);
		try {
			Mono<String> obj = (Mono<String>) argument.subscriberContext(context).block();
			fail("should not reach here");
		} catch(ClassCastException ex) {
		}
		ReactiveSecurityContextHolder.clearContext();
	}

	void securityContext(@CurrentSecurityContext Mono<SecurityContext> monoSecurityContext) {}

	void securityContextWithAuthentication(@CurrentSecurityContext(expression = "authentication") Mono<Authentication> authentication) {}

	void securityContextWithDepthPropOptional(@CurrentSecurityContext(expression = "authentication?.principal") Mono<Object> principal) {}

	void securityContextWithDepthProp(@CurrentSecurityContext(expression = "authentication.principal") Mono<Object> principal) {}

	void securityContextWithDepthStringProp(@CurrentSecurityContext(expression = "authentication.principal") Mono<String> principal) {}

	void errorOnInvalidTypeWhenImplicit(@CurrentSecurityContext Mono<String> implicit) {}

	void errorOnInvalidTypeWhenExplicitFalse(@CurrentSecurityContext(errorOnInvalidType = false) Mono<String> implicit) {}

	void errorOnInvalidTypeWhenExplicitTrue(@CurrentSecurityContext(errorOnInvalidType = true) Mono<String> implicit) {}


	private Authentication buildAuthenticationWithPrincipal(Object principal) {
		return new TestingAuthenticationToken(principal, "password",
				"ROLE_USER");
	}
}
