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

package org.springframework.security.aot.hint;

import org.junit.jupiter.api.Test;

import org.springframework.aot.generate.GenerationContext;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.aot.test.generate.TestGenerationContext;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.method.AuthorizeReturnObject;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

class PrePostAuthorizeHintsRegistrarTests {

	private final PrePostAuthorizeHintsRegistrar registrar = new PrePostAuthorizeHintsRegistrar();

	private final GenerationContext generationContext = new TestGenerationContext();

	@Test
	void registerHintsWhenPreAuthorizeOnTypeThenHintsRegistered() {
		process(Authz.class, PreAuthorizeOnClass.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void registerHintsWhenPostAuthorizeOnTypeThenHintsRegistered() {
		process(Authz.class, PostAuthorizeOnClass.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void registerHintsWhenPreAuthorizeOnMethodsThenHintsRegistered() {
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
	void registerHintsWhenPostAuthorizeOnMethodsThenHintsRegistered() {
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
	void registerHintsWhenPreAuthorizeExpressionWithMultipleBeansThenRegisterHintsForAllBeans() {
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
	void registerHintsWhenPostAuthorizeExpressionWithMultipleBeansThenRegisterHintsForAllBeans() {
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
	void registerHintsWhenPreAuthorizeOnTypeAndMethodThenRegisterHintsForBoth() {
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
	void registerHintsWhenPostAuthorizeOnTypeAndMethodThenRegisterHintsForBoth() {
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

	@Test
	void registerHintsWhenSecurityAnnotationsInsideAuthorizeReturnObjectOnMethodThenRegisterHints() {
		process(AccountAuthz.class, Authz.class, PreAuthorizeInsideAuthorizeReturnObjectOnMethod.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(AccountAuthz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void registerHintsWhenSecurityAnnotationsInsideAuthorizeReturnObjectOnClassThenRegisterHints() {
		process(AccountAuthz.class, Authz.class, PreAuthorizeInsideAuthorizeReturnObjectOnClass.class);
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(AccountAuthz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
		assertThat(RuntimeHintsPredicates.reflection()
			.onType(Authz.class)
			.withMemberCategory(MemberCategory.INVOKE_DECLARED_METHODS))
			.accepts(this.generationContext.getRuntimeHints());
	}

	@Test
	void registerHintsWhenCyclicDependencyThenNoStackOverflowException() {
		assertThatNoException().isThrownBy(() -> process(AService.class));
	}

	private void process(Class<?>... beanClasses) {
		DefaultListableBeanFactory beanFactory = new DefaultListableBeanFactory();
		for (Class<?> beanClass : beanClasses) {
			beanFactory.registerBeanDefinition(beanClass.getSimpleName().toLowerCase(),
					new RootBeanDefinition(beanClass));
		}
		this.registrar.registerHints(this.generationContext.getRuntimeHints(), beanFactory);
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

	static class PreAuthorizeInsideAuthorizeReturnObjectOnMethod {

		@AuthorizeReturnObject
		Account getAccount() {
			return new Account("1234");
		}

	}

	@AuthorizeReturnObject
	static class PreAuthorizeInsideAuthorizeReturnObjectOnClass {

		Account getAccount() {
			return new Account("1234");
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

	static class AccountAuthz {

		boolean canViewAccountNumber() {
			return true;
		}

	}

	static class Account {

		private final String accountNumber;

		Account(String accountNumber) {
			this.accountNumber = accountNumber;
		}

		@PreAuthorize("@accountauthz.canViewAccountNumber()")
		String getAccountNumber() {
			return this.accountNumber;
		}

		@AuthorizeReturnObject
		User getUser() {
			return new User("John Doe");
		}

	}

	static class User {

		private final String fullName;

		User(String fullName) {
			this.fullName = fullName;
		}

		@PostAuthorize("@authz.check()")
		String getFullName() {
			return this.fullName;
		}

	}

	static class AService {

		@AuthorizeReturnObject
		A getA() {
			return new A();
		}

	}

	static class A {

		@AuthorizeReturnObject
		B getB() {
			return null;
		}

	}

	static class B {

		@AuthorizeReturnObject
		A getA() {
			return null;
		}

	}

}
