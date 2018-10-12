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

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.util.ReactiveMethodInvocation;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
@RunWith(MockitoJUnitRunner.class)
public class ExpressionBasedReactivePostInvocationAuthorizationAdviceTests {
	@Spy
	private ReactiveMethodSecurityExpressionHandler expressionHandler = new DefaultReactiveMethodSecurityExpressionHandler();
	private ExpressionBasedReactivePostInvocationAuthorizationAdvice postAdvice;
	private Methods methods = new Methods();
	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	@Before
	public void setup() {
		this.postAdvice = new ExpressionBasedReactivePostInvocationAuthorizationAdvice(this.expressionHandler);
	}

	@Test
	public void nullPostInvocationAttribute() {
		Mono<String> mono = this.methods.postAuthorizeMono();
		StepVerifier.create(this.postAdvice.after(this.anonymous, new ReactiveMethodInvocation(this.methods, "postAuthorizeMono"), null, mono))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		verifyReturnObject(mono);
	}

	@Test
	public void postAuthorizeMonoTrue() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeMono");
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(null, String.format("T(%s).trueMono()", Methods.class.getName()));

		Mono<String> mono = this.methods.postAuthorizeMono();

		StepVerifier.create(this.postAdvice.after(this.anonymous, invocation, attr, mono))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		verifyReturnObject(mono);
	}

	@Test
	public void postAuthorizeMonoFalse() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeMono");
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(null, String.format("T(%s).falseMono()", Methods.class.getName()));

		Mono<String> mono = this.methods.postAuthorizeMono();

		StepVerifier.create(this.postAdvice.after(this.anonymous, invocation, attr, mono))
				.verifyErrorSatisfies(error -> {
					assertThat(error)
							.isNotNull()
							.isExactlyInstanceOf(AccessDeniedException.class)
							.hasMessage("Access is denied")
							.hasNoCause();
				});

		verifyReturnObject(mono);
	}

	@Test
	public void postAuthorizeFluxTrue() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeFlux");
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(null, String.format("T(%s).trueMono()", Methods.class.getName()));

		Flux<String> flux = this.methods.postAuthorizeFlux();

		StepVerifier.create(this.postAdvice.after(this.anonymous, invocation, attr, flux))
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();

		verifyReturnObject(flux);
	}

	@Test
	public void postAuthorizeFluxFalse() {
		MethodInvocation invocation = new ReactiveMethodInvocation(this.methods, "postAuthorizeFlux");
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(null, String.format("T(%s).falseMono()", Methods.class.getName()));

		Flux<String> flux = this.methods.postAuthorizeFlux();

		StepVerifier.create(this.postAdvice.after(this.anonymous, invocation, attr, flux))
				.verifyErrorSatisfies(error -> {
					assertThat(error)
							.isNotNull()
							.isExactlyInstanceOf(AccessDeniedException.class)
							.hasMessage("Access is denied")
							.hasNoCause();
				});

		verifyReturnObject(flux);
	}

	@Test
	public void postFilterMonoPasses() {
		Mono<String> postFilterInput = Mono.just(Methods.getSomething());
		Mono<String> mono = this.methods.postFilter(postFilterInput);
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).allPassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "postFilter", postFilterInput);
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(filterExpression, null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> invocation.getArgument(0));

		StepVerifier.create(this.postAdvice.after(this.anonymous, mi, attr, mono))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		verifyReturnObject(mono);
	}

	@Test
	public void postFilterMonDoesntPass() {
		Mono<String> postFilterInput = Mono.just(Methods.getSomethingElse());
		Mono<String> filteredInput = postFilterInput.filterWhen(Methods::onePassFilter);
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).onePassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "postFilter", postFilterInput);
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(filterExpression, null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> filteredInput);

		StepVerifier.create(this.postAdvice.after(this.anonymous, mi, attr, this.methods.postFilter(postFilterInput)))
				.verifyComplete();

		verifyReturnObject(filteredInput);
	}

	@Test
	public void postFilterFluxAllPass() {
		Flux<String> postFilterInput = Flux.just(Methods.getSomething(), Methods.getSomethingElse());
		Flux<String> flux = this.methods.postFilter(postFilterInput);
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).allPassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "postFilter", postFilterInput);
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(filterExpression, null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> invocation.getArgument(0));

		StepVerifier.create(this.postAdvice.after(this.anonymous, mi, attr, flux))
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();

		verifyReturnObject(flux);
	}

	@Test
	public void postFilterFluxSomePass() {
		Flux<String> postFilterInput = Flux.just(Methods.getSomething(), Methods.getSomethingElse());
		Flux<String> filteredInput = postFilterInput.filterWhen(Methods::onePassFilter);
		Expression filterExpression = this.expressionHandler.getExpressionParser().parseExpression(String.format("T(%s).onePassFilter(filterObject)", Methods.class.getName()));
		MethodInvocation mi = new ReactiveMethodInvocation(this.methods, "postFilter", postFilterInput);
		PostInvocationAttribute attr = new PostInvocationExpressionAttribute(filterExpression, null);
		given(this.expressionHandler.filter(any(Publisher.class), eq(filterExpression), any(EvaluationContext.class)))
				.willAnswer(invocation -> filteredInput);

		StepVerifier.create(this.postAdvice.after(this.anonymous, mi, attr, this.methods.postFilter(postFilterInput)))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		verifyReturnObject(filteredInput);
	}

	private <P extends Publisher<?>> void verifyReturnObject(P publisher) {
		verify(this.expressionHandler)
				.setReturnObject(eq(publisher), any(EvaluationContext.class));
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

		public Mono<String> postAuthorizeMono() {
			return Mono.just(getSomething());
		}

		public Flux<String> postAuthorizeFlux() {
			return Flux.just(getSomething(), getSomethingElse());
		}

		public Mono<String> postFilter(Mono<String> mono) {
			return mono;
		}

		public Flux<String> postFilter(Flux<String> flux) {
			return flux;
		}

		public static Mono<Boolean> allPassFilter(String string) {
			return Mono.just(true);
		}

		public static Mono<Boolean> onePassFilter(String string) {
			return Mono.just(getSomething().equals(string));
		}
	}
}
