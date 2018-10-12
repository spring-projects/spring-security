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
package org.springframework.security.access.expression;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.expression.EvaluationException;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

/**
 * @author Eric Deandrea
 * @since 5.1.2
 */
public class ReactiveExpressionUtilsTests {
	private StandardEvaluationContext ctx = new StandardEvaluationContext();
	private ExpressionParser expressionParser = new SpelExpressionParser();

	@Before
	public void setup() {
		this.ctx.setVariable("methods", new Methods());
	}

	@Test
	public void returnsBooleanPrimitive() {
		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnTrue()"), this.ctx))
				.expectNext(true)
				.verifyComplete();

		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnFalse()"), this.ctx))
				.expectNext(false)
				.verifyComplete();
	}

	@Test
	public void returnsBooleanMono() {
		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnMonoTrue()"), this.ctx))
				.expectNext(true)
				.verifyComplete();

		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnMonoFalse()"), this.ctx))
				.expectNext(false)
				.verifyComplete();
	}

	@Test
	public void errorsOnSomethingOtherThanBoolean() {
		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnSomethingElse()"), ctx))
				.verifyErrorSatisfies(ex -> {
					assertThat(ex)
						.isNotNull()
						.isExactlyInstanceOf(IllegalArgumentException.class)
						.hasMessage("Expression '#methods.returnSomethingElse()' needs to either return boolean or Mono<Boolean> but it does not");
				});

		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnMonoSomethingElse()"), ctx))
				.verifyErrorSatisfies(ex -> {
					assertThat(ex)
							.isNotNull()
							.isExactlyInstanceOf(IllegalArgumentException.class)
							.hasMessage("Expression '#methods.returnMonoSomethingElse()' needs to either return boolean or Mono<Boolean> but it does not");
				});
	}

	@Test
	public void someOtherError() {
		// Expression that doesn't exist
		StepVerifier.create(ReactiveExpressionUtils.evaluateAsBoolean(this.expressionParser.parseExpression("#methods.returnAnotherThing()"), ctx))
				.verifyErrorSatisfies(ex -> {
					assertThat(ex)
							.isNotNull()
							.isExactlyInstanceOf(IllegalArgumentException.class)
							.hasMessage("Failed to evaluate expression '#methods.returnAnotherThing()': EL1004E: Method call: Method returnAnotherThing() cannot be found on type org.springframework.security.access.expression.ReactiveExpressionUtilsTests$Methods")
							.hasCauseInstanceOf(EvaluationException.class);
				});
	}

	class Methods {
		public boolean returnTrue() {
			return true;
		}

		public boolean returnFalse() {
			return false;
		}

		public Mono<Boolean> returnMonoTrue() {
			return Mono.fromSupplier(this::returnTrue);
		}

		public Mono<Boolean> returnMonoFalse() {
			return Mono.fromSupplier(this::returnFalse);
		}

		public String returnSomethingElse() {
			return "Something Else";
		}

		public Mono<String> returnMonoSomethingElse() {
			return Mono.fromSupplier(this::returnSomethingElse);
		}
	}
}
