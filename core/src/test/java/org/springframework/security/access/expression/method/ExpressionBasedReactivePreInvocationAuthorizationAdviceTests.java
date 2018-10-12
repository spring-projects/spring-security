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
package org.springframework.security.access.expression.method;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.BDDMockito.*;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Spy;
import org.mockito.junit.MockitoJUnitRunner;
import org.reactivestreams.Publisher;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.util.ReactiveMethodInvocation;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
@RunWith(MockitoJUnitRunner.class)
public class ExpressionBasedReactivePreInvocationAuthorizationAdviceTests {
	@Spy
	private ReactiveMethodSecurityExpressionHandler expressionHandler = new DefaultReactiveMethodSecurityExpressionHandler();
	private ExpressionBasedReactivePreInvocationAuthorizationAdvice preAdvice;
	private Methods methods = new Methods();
	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Before
	public void setup() {
		this.preAdvice = new ExpressionBasedReactivePreInvocationAuthorizationAdvice(this.expressionHandler);
	}

	@Test
	public void nullPreInvocationAttribute() {
		StepVerifier.create(this.preAdvice.before(this.anonymous, new ReactiveMethodInvocation(this.methods, "preAuthorizeMono"), null))
				.expectNext(true)
				.verifyComplete();
	}

	@Test
	public void preAuthorizeMonoTrue() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeMono");
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(null, "", String.format("T(%s).trueMono()", Methods.class.getName()));

		StepVerifier.create(this.preAdvice.before(this.anonymous, invocation, attr))
				.expectNext(true)
				.verifyComplete();
	}

	@Test
	public void preAuthorizeMonoFalse() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeMono");
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(null, "", String.format("T(%s).falseMono()", Methods.class.getName()));

		StepVerifier.create(this.preAdvice.before(this.anonymous, invocation, attr))
				.expectNext(false)
				.verifyComplete();
	}

	@Test
	public void preAuthorizeFluxTrue() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "preAuthorizeFlux");
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(null, "", String.format("T(%s).trueMono()", Methods.class.getName()));

		StepVerifier.create(this.preAdvice.before(this.anonymous, invocation, attr))
				.expectNext(true)
				.verifyComplete();
	}

	@Test
	public void preAuthorizeFluxFalse() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preAuthorizeFlux");
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(null, "", String.format("T(%s).falseMono()", Methods.class.getName()));

		StepVerifier.create(this.preAdvice.before(this.anonymous, mi, attr))
				.expectNext(false)
				.verifyComplete();
	}

	@Test
	public void applyFilterTargetFromArgument() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preFilter", Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);
		ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", null, null, ctx, mi);

		assertThat(mi.getArguments())
				.isNotNull()
				.isNotEmpty()
				.hasSize(1);

		StepVerifier.create((Flux<String>) mi.getArguments()[0])
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void applyFilterTargetNoFilterTargetFound() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preAuthorizeFlux");
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);
		ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", null, null, ctx, mi);

		assertThat(mi.getArguments())
				.isNotNull()
				.isEmpty();
	}

	@Test
	public void applyFilterTargetFromMethodWithMono() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preFilterWithNoFluxArg", Mono.just(Methods.getSomething()));
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);
		ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", null, null, ctx, mi);

		assertThat(mi.getArguments())
				.isNotNull()
				.isNotEmpty()
				.hasSize(1);

		StepVerifier.create((Mono<String>) mi.getArguments()[0])
				.expectNext(Methods.getSomething())
				.verifyComplete();
	}

	@Test
	public void applyFilterTargetWhenMultipleArgumentsVariableNotSpecified() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods,
				"preFilterWithMultipleArgs",
				Mono.just(Methods.getSomething()),
				Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);
		ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", null, null, ctx, mi);

		assertThat(mi.getArguments())
				.isNotNull()
				.isNotEmpty()
				.hasSize(2);

		verify(this.expressionHandler, never()).filter(any(Publisher.class), any(Expression.class), eq(ctx));
	}

	@Test
	public void applyFilterTargetWhenMultipleArgumentsVariableSpecifiedNotFound() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods,
				"preFilterWithMultipleArgs",
				Mono.just(Methods.getSomething()),
				Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", "someFlux1", null, ctx, mi))
				.withMessage("Filter target was null, or no argument with name someFlux1 found in method")
				.withNoCause();
	}

	@Test
	public void applyFilterTargetFromNonReactiveArgument() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods,
				"preFilter",
				Methods.getSomething()
		);
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", null, null, ctx, mi))
				.withMessage(String.format("A PreFilter expression was set but the method argument type %s is not a %s", String.class, Publisher.class.getName()))
				.withNoCause();
	}

	@Test
	public void applyFilterTargetWhenMultipleArgumentsVariableSpecified() {
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods,
				"preFilterWithMultipleArgs",
				Mono.just(Methods.getSomething()),
				Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(this.anonymous, mi);
		ReflectionTestUtils.invokeMethod(this.preAdvice, "applyFilterTarget", "someFlux", null, ctx, mi);

		assertThat(mi.getArguments())
				.isNotNull()
				.isNotEmpty()
				.hasSize(2);

		StepVerifier.create((Flux<String>) mi.getArguments()[1])
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();
	}

	@Test
	public void preFilterAllPass() {
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).allPassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preFilter", Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(filterExpression, "", null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> invocation.getArgument(0));

		StepVerifier.create(this.preAdvice.before(this.anonymous, mi, attr))
				.expectNext(true)
				.verifyComplete();

		verify(this.expressionHandler).filter(any(Flux.class), eq(filterExpression), any(EvaluationContext.class));
	}

	@Test
	public void preFilterSomePass() {
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).onePassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "preFilter", Flux.just(Methods.getSomething(), Methods.getSomethingElse()));
		PreInvocationAttribute attr = new PreInvocationExpressionAttribute(filterExpression, "", null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> invocation.<Flux<String>>getArgument(0).filterWhen(Methods::onePassFilter));

		StepVerifier.create(this.preAdvice.before(this.anonymous, mi, attr))
				.expectNext(true)
				.verifyComplete();

		verify(this.expressionHandler).filter(any(Flux.class), eq(filterExpression), any(EvaluationContext.class));
	}

	private static class Methods {
		public static String getSomething() {
			return "something";
		}

		public static String getSomethingElse() {
			return "something else";
		}

		public static Mono<Boolean> trueMono() {
			return Mono.just(true);
		}

		public static Mono<Boolean> falseMono() {
			return Mono.just(false);
		}

		public Mono<String> preAuthorizeMono() {
			return Mono.just(getSomething());
		}

		public Flux<String> preAuthorizeFlux() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		public Flux<String> preFilter(Flux<String> flux) {
			return flux;
		}

		public Mono<String> preFilter(String string) {
			return Mono.just(string);
		}

		public Flux<String> preFilterWithNoFluxArg(Mono<String> someMono) {
			return someMono.flux();
		}

		public Flux<String> preFilterWithMultipleArgs(Mono<String> someMono, Flux<String> someFlux) {
			return someFlux;
		}

		public static Mono<Boolean> allPassFilter(String string) {
			return Mono.just(true);
		}

		public static Mono<Boolean> onePassFilter(String string) {
			return Mono.just(getSomething().equals(string));
		}
	}
}
