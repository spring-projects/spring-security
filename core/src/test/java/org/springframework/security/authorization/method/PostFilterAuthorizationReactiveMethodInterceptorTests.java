/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostFilter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PostFilterAuthorizationReactiveMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class PostFilterAuthorizationReactiveMethodInterceptorTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor(
				expressionHandler);
		assertThat(interceptor).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new PostFilterAuthorizationReactiveMethodInterceptor(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPostFilterAnnotationThenNotMatches() throws Exception {
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		assertThat(interceptor.getPointcut().getMethodMatcher()
				.matches(NoPostFilterClass.class.getMethod("doSomething"), NoPostFilterClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPostFilterAnnotationThenMatches() throws Exception {
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		assertThat(interceptor.getPointcut().getMethodMatcher()
				.matches(TestClass.class.getMethod("doSomethingFlux", Flux.class), TestClass.class)).isTrue();
	}

	@Test
	public void invokeWhenMonoThenFilteredMono() throws Throwable {
		Mono<String> mono = Mono.just("bob");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingMono", new Class[] { Mono.class }, new Object[] { mono }) {
			@Override
			public Object proceed() {
				return mono;
			}
		};
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		Object result = interceptor.invoke(methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class)).extracting(Mono::block).isNull();
	}

	@Test
	public void invokeWhenFluxThenFilteredFlux() throws Throwable {
		Flux<String> flux = Flux.just("john", "bob");
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingFluxClassLevel", new Class[] { Flux.class }, new Object[] { flux }) {
			@Override
			public Object proceed() {
				return flux;
			}
		};
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		Object result = interceptor.invoke(methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class)).extracting(Flux::collectList)
				.extracting(Mono::block, InstanceOfAssertFactories.list(String.class)).containsOnly("john");
	}

	@Test
	public void checkInheritedAnnotationsWhenDuplicatedThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"inheritedAnnotations");
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> interceptor.invoke(methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ConflictingAnnotations(),
				ConflictingAnnotations.class, "inheritedAnnotations");
		PostFilterAuthorizationReactiveMethodInterceptor interceptor = new PostFilterAuthorizationReactiveMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> interceptor.invoke(methodInvocation));
	}

	@PostFilter("filterObject == 'john'")
	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		@PostFilter("filterObject == 'john'")
		public Flux<String> doSomethingFlux(Flux<String> flux) {
			return flux;
		}

		public Flux<String> doSomethingFluxClassLevel(Flux<String> flux) {
			return flux;
		}

		@PostFilter("filterObject == 'john'")
		public Mono<String> doSomethingMono(Mono<String> mono) {
			return mono;
		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	public static class NoPostFilterClass {

		public void doSomething() {

		}

	}

	public static class ConflictingAnnotations implements InterfaceAnnotationsThree {

		@Override
		@PostFilter("filterObject == 'jack'")
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@PostFilter("filterObject == 'jim'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@PostFilter("filterObject == 'jane'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MyPostFilter
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PostFilter("filterObject == 'john'")
	public @interface MyPostFilter {

	}

}
