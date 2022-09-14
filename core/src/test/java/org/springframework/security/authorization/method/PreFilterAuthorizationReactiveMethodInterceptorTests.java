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

import org.springframework.core.ParameterNameDiscoverer;
import org.springframework.core.annotation.AnnotationConfigurationException;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.core.parameters.DefaultSecurityParameterNameDiscoverer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link PreFilterAuthorizationReactiveMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class PreFilterAuthorizationReactiveMethodInterceptorTests {

	@Test
	public void setExpressionHandlerWhenNotNullThenSetsExpressionHandler() {
		MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor(
				expressionHandler);
		assertThat(interceptor).extracting("registry").extracting("expressionHandler").isEqualTo(expressionHandler);
	}

	@Test
	public void setExpressionHandlerWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new PreFilterAuthorizationReactiveMethodInterceptor(null))
				.withMessage("expressionHandler cannot be null");
	}

	@Test
	public void setParameterNameDiscovererWhenNotNullThenSetsParameterNameDiscoverer() {
		ParameterNameDiscoverer parameterNameDiscoverer = new DefaultSecurityParameterNameDiscoverer();
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		interceptor.setParameterNameDiscoverer(parameterNameDiscoverer);
		assertThat(interceptor).extracting("parameterNameDiscoverer").isEqualTo(parameterNameDiscoverer);
	}

	@Test
	public void setParameterNameDiscovererWhenNullThenException() {
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThatIllegalArgumentException().isThrownBy(() -> interceptor.setParameterNameDiscoverer(null))
				.withMessage("parameterNameDiscoverer cannot be null");
	}

	@Test
	public void methodMatcherWhenMethodHasNotPreFilterAnnotationThenNotMatches() throws Exception {
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThat(interceptor.getPointcut().getMethodMatcher().matches(NoPreFilterClass.class.getMethod("doSomething"),
				NoPreFilterClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenMethodHasPreFilterAnnotationThenMatches() throws Exception {
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThat(interceptor.getPointcut().getMethodMatcher()
				.matches(TestClass.class.getMethod("doSomethingFluxFilterTargetMatch", Flux.class), TestClass.class))
						.isTrue();
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndNotMatchThenException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingFluxFilterTargetNotMatch", new Class[] { Flux.class }, new Object[] { Flux.empty() });
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThatIllegalArgumentException().isThrownBy(() -> interceptor.invoke(methodInvocation)).withMessage(
				"Filter target was null, or no argument with name 'filterTargetNotMatch' found in method.");
	}

	@Test
	public void findFilterTargetWhenNameProvidedAndMatchAndNullThenException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingFluxFilterTargetMatch", new Class[] { Flux.class }, new Object[] { null });
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThatIllegalArgumentException().isThrownBy(() -> interceptor.invoke(methodInvocation))
				.withMessage("Filter target was null, or no argument with name 'flux' found in method.");
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgMonoThenFiltersMono() throws Throwable {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingMonoFilterTargetNotProvided", new Class[] { Mono.class },
				new Object[] { Mono.just("bob") }) {
			@Override
			public Object proceed() {
				return getArguments()[0];
			}
		};
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		Object result = interceptor.invoke(methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Mono.class)).extracting(Mono::block).isNull();
	}

	@Test
	public void findFilterTargetWhenNameNotProvidedAndSingleArgFluxThenFiltersFlux() throws Throwable {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomethingFluxFilterTargetNotProvided", new Class[] { Flux.class },
				new Object[] { Flux.just("john", "bob") }) {
			@Override
			public Object proceed() {
				return getArguments()[0];
			}
		};
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		Object result = interceptor.invoke(methodInvocation);
		assertThat(result).asInstanceOf(InstanceOfAssertFactories.type(Flux.class)).extracting(Flux::collectList)
				.extracting(Mono::block, InstanceOfAssertFactories.list(String.class)).containsOnly("john");
	}

	@Test
	public void checkInheritedAnnotationsWhenDuplicatedThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"inheritedAnnotations");
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> interceptor.invoke(methodInvocation));
	}

	@Test
	public void checkInheritedAnnotationsWhenConflictingThenAnnotationConfigurationException() throws Exception {
		MockMethodInvocation methodInvocation = new MockMethodInvocation(new ConflictingAnnotations(),
				ConflictingAnnotations.class, "inheritedAnnotations");
		PreFilterAuthorizationReactiveMethodInterceptor interceptor = new PreFilterAuthorizationReactiveMethodInterceptor();
		assertThatExceptionOfType(AnnotationConfigurationException.class)
				.isThrownBy(() -> interceptor.invoke(methodInvocation));
	}

	@PreFilter("filterObject == 'john'")
	public static class TestClass implements InterfaceAnnotationsOne, InterfaceAnnotationsTwo {

		@PreFilter(value = "filterObject == 'john'", filterTarget = "filterTargetNotMatch")
		public Flux<String> doSomethingFluxFilterTargetNotMatch(Flux<String> flux) {
			return flux;
		}

		@PreFilter(value = "filterObject == 'john'", filterTarget = "flux")
		public Flux<String> doSomethingFluxFilterTargetMatch(Flux<String> flux) {
			return flux;
		}

		@PreFilter("filterObject == 'john'")
		public Flux<String> doSomethingFluxFilterTargetNotProvided(Flux<String> flux) {
			return flux;
		}

		@PreFilter("filterObject == 'john'")
		public Mono<String> doSomethingMonoFilterTargetNotProvided(Mono<String> mono) {
			return mono;
		}

		public Flux<String> doSomethingTwoArgsFilterTargetNotProvided(String s, Flux<String> flux) {
			return flux;
		}

		@Override
		public void inheritedAnnotations() {

		}

	}

	public static class NoPreFilterClass {

		public void doSomething() {

		}

	}

	public static class ConflictingAnnotations implements InterfaceAnnotationsThree {

		@Override
		@PreFilter("filterObject == 'jack'")
		public void inheritedAnnotations() {

		}

	}

	public interface InterfaceAnnotationsOne {

		@PreFilter("filterObject == 'jim'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsTwo {

		@PreFilter("filterObject == 'jane'")
		void inheritedAnnotations();

	}

	public interface InterfaceAnnotationsThree {

		@MyPreFilter
		void inheritedAnnotations();

	}

	@Retention(RetentionPolicy.RUNTIME)
	@PreFilter("filterObject == 'john'")
	public @interface MyPreFilter {

	}

}
