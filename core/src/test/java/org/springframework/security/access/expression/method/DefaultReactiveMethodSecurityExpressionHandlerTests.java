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

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
@RunWith(MockitoJUnitRunner.class)
public class DefaultReactiveMethodSecurityExpressionHandlerTests {
	private DefaultReactiveMethodSecurityExpressionHandler handler = new DefaultReactiveMethodSecurityExpressionHandler();

	@Mock
	private Authentication authentication;

	@Mock
	private MethodInvocation methodInvocation;

	@After
	public void cleanup() {
		Mono<SecurityContext> context = Mono.subscriberContext()
				.flatMap( c -> ReactiveSecurityContextHolder.getContext())
				.subscriberContext(ReactiveSecurityContextHolder.clearContext());

		StepVerifier.create(context)
				.verifyComplete();
	}

	@Test
	public void setTrustResolverNull() {
		assertThatThrownBy(() -> this.handler.setTrustResolver(null))
				.isExactlyInstanceOf(IllegalArgumentException.class);
	}

	@Test
	public void setPermissionCacheOptimizerIsInvalid() {
		assertThatThrownBy(() -> this.handler.setPermissionCacheOptimizer((authentication1, objects) -> {}))
				.isExactlyInstanceOf(UnsupportedOperationException.class)
				.hasMessage("PermissionCacheOptimizer is not yet supported on the reactive stack!")
				.hasNoCause();
	}

	@Test
	public void nullFilterExpression() {
		EvaluationContext ctx = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);

		StepVerifier.create(this.handler.filter(Mono.just(Methods.getSomething()), null, ctx))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		assertFilterObject(null, ctx);
	}

	@Test
	public void monoPasses() {
		Expression expression = this.handler.getExpressionParser().parseExpression(String.format("T(%s).trueMono()", Methods.class.getName()));
		EvaluationContext ctx = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);

		StepVerifier.create(this.handler.filter(Mono.just(Methods.getSomething()), expression, ctx))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		assertFilterObject(Methods.getSomething(), ctx);
	}

	@Test
	public void monoDoesntPass() {
		Expression expression = this.handler.getExpressionParser().parseExpression(String.format("T(%s).falseMono()", Methods.class.getName()));
		EvaluationContext ctx = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);

		StepVerifier.create(this.handler.filter(Mono.just(Methods.getSomething()), expression, ctx))
				.verifyComplete();

		assertFilterObject(Methods.getSomething(), ctx);
	}

	@Test
	public void fluxAllPasses() {
		Expression expression = this.handler.getExpressionParser().parseExpression(String.format("T(%s).allPassFilter(filterObject)", Methods.class.getName()));
		EvaluationContext ctx = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);

		StepVerifier.create(this.handler.filter(Flux.just(Methods.getSomething(), Methods.getSomethingElse()), expression, ctx))
				.expectNext(Methods.getSomething())
				.expectNext(Methods.getSomethingElse())
				.verifyComplete();

		assertFilterObject(Methods.getSomethingElse(), ctx);
	}

	@Test
	public void fluxSomePass() {
		Expression expression = this.handler.getExpressionParser().parseExpression(String.format("T(%s).onePassFilter(filterObject)", Methods.class.getName()));
		EvaluationContext ctx = this.handler.createEvaluationContext(this.authentication, this.methodInvocation);

		StepVerifier.create(this.handler.filter(Flux.just(Methods.getSomething(), Methods.getSomethingElse()), expression, ctx))
				.expectNext(Methods.getSomething())
				.verifyComplete();

		assertFilterObject(Methods.getSomethingElse(), ctx);
	}

	private static <T> void assertFilterObject(T expectedFilterObject, EvaluationContext ctx) {
		MethodSecurityExpressionOperations rootObject = (MethodSecurityExpressionOperations) ctx.getRootObject().getValue();

		if (expectedFilterObject == null) {
			assertThat(rootObject.getFilterObject())
					.isNull();
		}
		else {
			assertThat(rootObject.getFilterObject())
					.isEqualTo(expectedFilterObject);
		}
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

		public static Mono<Boolean> allPassFilter(String string) {
			return Mono.just(true);
		}

		public static Mono<Boolean> onePassFilter(String string) {
			return Mono.just(getSomething().equals(string));
		}
	}
}
