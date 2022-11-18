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

package org.springframework.security.test.aot.hint;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.TypeReference;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.showcase.WithMockCustomUser;
import org.springframework.security.test.context.showcase.WithMockCustomUserSecurityContextFactory;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.security.test.context.support.WithUserDetails;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link WithSecurityContextTestRuntimeHints}.
 */
@WithMockCustomUser
class WithSecurityContextTestRuntimeHintsTests {

	private final RuntimeHints hints = new RuntimeHints();

	private final WithSecurityContextTestRuntimeHints registrar = new WithSecurityContextTestRuntimeHints();

	@BeforeEach
	void setup() {
		this.registrar.registerHints(this.hints, WithSecurityContextTestRuntimeHintsTests.class,
				WithSecurityContextTestRuntimeHintsTests.class.getClassLoader());
	}

	@Test
	@WithMockUser
	void withMockUserHasHints() {
		assertThat(RuntimeHintsPredicates.reflection()
				.onType(TypeReference
						.of("org.springframework.security.test.context.support.WithMockUserSecurityContextFactory"))
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Test
	@WithAnonymousUser
	void withAnonymousUserHasHints() {
		assertThat(RuntimeHintsPredicates.reflection()
				.onType(TypeReference.of(
						"org.springframework.security.test.context.support.WithAnonymousUserSecurityContextFactory"))
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Test
	@WithUserDetails
	void withUserDetailsHasHints() {
		assertThat(RuntimeHintsPredicates.reflection()
				.onType(TypeReference
						.of("org.springframework.security.test.context.support.WithUserDetailsSecurityContextFactory"))
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Test
	@WithMockTestUser
	void withMockTestUserHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(WithMockTestUserSecurityContextFactory.class)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Test
	void withMockCustomUserOnClassHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(WithMockCustomUserSecurityContextFactory.class)
				.withMemberCategory(MemberCategory.INVOKE_DECLARED_CONSTRUCTORS)).accepts(this.hints);
	}

	@Retention(RetentionPolicy.RUNTIME)
	@WithSecurityContext(factory = WithMockTestUserSecurityContextFactory.class)
	@interface WithMockTestUser {

	}

	static class WithMockTestUserSecurityContextFactory implements WithSecurityContextFactory<WithMockTestUser> {

		@Override
		public SecurityContext createSecurityContext(WithMockTestUser annotation) {
			return SecurityContextHolder.createEmptyContext();
		}

	}

}
