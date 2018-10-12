/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.access.prepost;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.any;
import static org.mockito.BDDMockito.eq;
import static org.mockito.BDDMockito.given;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import reactor.core.Exceptions;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.method.DefaultReactiveMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.ExpressionBasedAnnotationAttributeFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.ReactiveMethodInvocation;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
@RunWith(MockitoJUnitRunner.class)
public class ReactivePrePostAdviceMethodInterceptorTests {
	@Mock
	private ReactivePreInvocationAuthorizationAdvice preAdvice;

	@Mock
	private ReactivePostInvocationAuthorizationAdvice postAdvice;

	private Methods methods = new Methods();
	private ReactivePrePostAdviceMethodInterceptor methodInterceptor;

	@Before
	public void setup() {
		this.methodInterceptor = new ReactivePrePostAdviceMethodInterceptor(
				new PrePostAnnotationSecurityMetadataSource(
						new ExpressionBasedAnnotationAttributeFactory(
								new DefaultReactiveMethodSecurityExpressionHandler()
						)
				),
				this.preAdvice,
				this.postAdvice);
	}

	@Test
	public void nonReactiveMethod() {
		assertThatThrownBy(() -> this.methodInterceptor.invoke(new ReactiveMethodInvocation(this.methods, "getSomething")))
				.isExactlyInstanceOf(IllegalStateException.class)
				.hasMessage("The return type java.lang.String on method public java.lang.String org.springframework.security.access.prepost.ReactivePrePostAdviceMethodInterceptorTests$Methods.getSomething() must return an instance of org.reactivestreams.Publisher (i.e. Mono / Flux) in order to support Reactor Context")
				.hasNoCause();
	}

	@Test
	public void preAuthorizeMonoTrue() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeMonoTrue");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());

		Mono<String> p;

		try {
			p = (Mono<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.verifyComplete();
	}

	@Test
	public void preAuthorizeMonoFalse() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeMonoFalse");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.falseMono());

		Mono<String> p;

		try {
			p = (Mono<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void postAuthorizeMonoTrue() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeMonoTrue");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willReturn(this.methods.postAuthorizeMonoTrue());

		Mono<String> p;

		try {
			p = (Mono<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.verifyComplete();
	}

	@Test
	public void postAuthorizeMonoFalse() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeMonoFalse");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willReturn(Mono.error(new AccessDeniedException("Denied")));

		Mono<String> p;

		try {
			p = (Mono<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void preAuthorizeFluxTrue() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeFluxTrue");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.expectNext("something else")
				.verifyComplete();
	}

	@Test
	public void preAuthorizeFluxFalse() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeFluxFalse");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.falseMono());

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void postAuthorizeFluxTrue() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeFluxTrue");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willAnswer(invocation -> invocation.getArgument(3));

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.expectNext("something else")
				.verifyComplete();
	}

	@Test
	public void postAuthorizeFluxFalse() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeFluxFalse");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willReturn(Mono.error(new AccessDeniedException("Denied")));

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.verifyError(AccessDeniedException.class);
	}

	@Test
	public void preFilterAllPass() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preFilterAllPass", Flux.just(this.methods.getSomething(), this.methods.getSomethingElse()));
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(Mono.just(true));

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.expectNext("something else")
				.verifyComplete();
	}

	@Test
	public void preFilterOnePasses() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "preFilterOnePasses", Flux.just(this.methods.getSomething(), this.methods.getSomethingElse()));
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willAnswer(invocation -> {
					MethodInvocation mi = invocation.getArgument(1);
					mi.getArguments()[0] = ((Flux<String>) mi.getArguments()[0]).filterWhen(this.methods::onePassFilter);

					return this.methods.trueMono();
				});

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.verifyComplete();
	}

	@Test
	public void postFilterAllPass() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postFilterAllPass");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(this.methods.trueMono());
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willAnswer(invocation -> invocation.getArgument(3));

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.expectNext("something else")
				.verifyComplete();
	}

	@Test
	public void postFilterOnePasses() {
		MethodInvocation methodInvocation = new ReactiveMethodInvocation(this.methods, "postFilterOnePasses");
		given(this.preAdvice.before(any(Authentication.class), eq(methodInvocation), any(PreInvocationAttribute.class)))
				.willReturn(Mono.just(true));
		given(this.postAdvice.after(any(Authentication.class), eq(methodInvocation), any(PostInvocationAttribute.class), any()))
				.willAnswer(invocation -> ((Flux<String>) invocation.getArgument(3)).filterWhen(this.methods::onePassFilter));

		Flux<String> p;

		try {
			p = (Flux<String>) this.methodInterceptor.invoke(methodInvocation);
		}
		catch (Throwable t) {
			throw Exceptions.propagate(t);
		}

		StepVerifier.create(p)
				.expectNext("something")
				.verifyComplete();
	}

	private static class Methods {
		public String getSomething() {
			return "something";
		}

		public String getSomethingElse() {
			return "something else";
		}

		@PreAuthorize("trueMono()")
		public Mono<String> preAuthorizeMonoTrue() {
			return Mono.just(getSomething());
		}

		@PreAuthorize("falseMono()")
		public Mono<String> preAuthorizeMonoFalse() {
			return Mono.just(getSomething());
		}

		@PostAuthorize("trueMono()")
		public Mono<String> postAuthorizeMonoTrue() {
			return Mono.just(getSomething());
		}

		@PostAuthorize("falseMono()")
		public Mono<String> postAuthorizeMonoFalse() {
			return Mono.just(getSomething());
		}

		@PreAuthorize("trueMono()")
		public Flux<String> preAuthorizeFluxTrue() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PreAuthorize("falseMono()")
		public Flux<String> preAuthorizeFluxFalse() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostAuthorize("trueMono()")
		public Flux<String> postAuthorizeFluxTrue() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostAuthorize("falseMono()")
		public Flux<String> postAuthorizeFluxFalse() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PreFilter("allPassFilter(filterObject)")
		public Flux<String> preFilterAllPass(Flux<String> flux) {
			return flux;
		}

		@PreFilter("onePassFilter(filterObject)")
		public Flux<String> preFilterOnePasses(Flux<String> flux) {
			return flux;
		}

		@PostFilter("allPassFilter(filterObject)")
		public Flux<String> postFilterAllPass() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		@PostFilter("onePassFilter(filterObject)")
		public Flux<String> postFilterOnePasses() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		public Mono<Boolean> trueMono() {
			return Mono.just(true);
		}

		public Mono<Boolean> falseMono() {
			return Mono.just(false);
		}

		public Mono<Boolean> allPassFilter(String string) {
			return Mono.just(true);
		}

		public Mono<Boolean> onePassFilter(String string) {
			return Mono.just(getSomething().equals(string));
		}
	}
}
