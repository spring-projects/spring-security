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

package org.springframework.security.config.annotation.method.configuration;

import org.junit.jupiter.api.Test;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.aot.test.generate.TestGenerationContext;
import org.springframework.beans.factory.aot.BeanFactoryInitializationAotContribution;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link PrePostAuthorizeBeanFactoryInitializationAotProcessor}
 *
 * @author Marcus da Coregio
 */
class PrePostAuthorizeBeanFactoryInitializationAotProcessorTests {

	private final PrePostAuthorizeBeanFactoryInitializationAotProcessor processor = new PrePostAuthorizeBeanFactoryInitializationAotProcessor();

	private final GenerationContext generationContext = new TestGenerationContext();

	@Test
	void processWhenPreAuthorizeOnTypeThenProcessed() {
		process(Authz.class, PreAuthorizeOnClass.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPostAuthorizeOnTypeThenProcessed() {
		process(Authz.class, PostAuthorizeOnClass.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPreAuthorizeOnMethodsThenProcessed() {
		process(Authz.class, Foo.class, PreAuthorizeOnMethods.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPostAuthorizeOnMethodsThenProcessed() {
		process(Authz.class, Foo.class, PostAuthorizeOnMethods.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPreAuthorizeExpressionWithMultipleBeansThenRegisterHintsForAllBeans() {
		process(Authz.class, Foo.class, PreAuthorizeMultipleBeans.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPostAuthorizeExpressionWithMultipleBeansThenRegisterHintsForAllBeans() {
		process(Authz.class, Foo.class, PostAuthorizeMultipleBeans.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPreAuthorizeOnTypeAndMethodThenRegisterHintsForBoth() {
		process(Authz.class, Foo.class, PreAuthorizeOnTypeAndMethod.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void processWhenPostAuthorizeOnTypeAndMethodThenRegisterHintsForBoth() {
		process(Authz.class, Foo.class, PostAuthorizeOnTypeAndMethod.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Foo.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	private void process(Class<?>... beanClasses) {
		DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
		for (Class<?> beanClass : beanClasses) {
			beanFactory.registerBeanDefinition(beanClass.getSimpleName().toLowerCase(),
					new RootBeanDefinition(beanClass));
		}
		BeanFactoryInitializationAotContribution contribution = this.processor.processAheadOfTime(beanFactory);
		assertThat(contribution).isNotNull();
		contribution.applyTo(this.generationContext, mock());
	}

	@PreAuthorize("@authz.check()")
	static class PreAuthorizeOnClass {

	}

	@PostAuthorize("@authz.check()")
	static class PostAuthorizeOnClass {

	}

	static class PreAuthorizeOnMethods {

		@PreAuthorize("@authz.check()")
		void method1() {
		}

		@PreAuthorize("@foo.bar()")
		void method2() {
		}

	}

	static class PostAuthorizeOnMethods {

		@PostAuthorize("@authz.check()")
		void method1() {
		}

		@PostAuthorize("@foo.bar()")
		void method2() {
		}

	}

	static class PreAuthorizeMultipleBeans {

		@PreAuthorize("@authz.check() ? true : @foo.bar()")
		void method1() {
		}

	}

	static class PostAuthorizeMultipleBeans {

		@PostAuthorize("@authz.check() ? true : @foo.bar()")
		void method1() {
		}

	}

	@PreAuthorize("@authz.check()")
	static class PreAuthorizeOnTypeAndMethod {

		@PreAuthorize("@foo.bar()")
		void method1() {
		}

	}

	@PostAuthorize("@authz.check()")
	static class PostAuthorizeOnTypeAndMethod {

		@PostAuthorize("@foo.bar()")
		void method1() {
		}

	}

	static class Authz {

		boolean check() {
			return true;
		}

	}

	static class Foo {

		boolean bar() {
			return true;
		}

	}

}
