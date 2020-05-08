/*
 * Copyright 2002-2020 the original author or authors.
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
package org.springframework.security.test.context.support;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.core.annotation.AnnotatedElementUtils;

public class WithMockOidcUserTests {

	@Test
	public void defaults() {
		WithMockOidcUser mockUser = AnnotatedElementUtils.findMergedAnnotation(Annotated.class,
				WithMockOidcUser.class);
		assertThat(mockUser.value()).isEqualTo("user");
		assertThat(mockUser.name()).isEmpty();
		assertThat(mockUser.authorities()).containsOnly(WithMockOidcUser.DEFAULT_SCOPE);
		assertThat(mockUser.clientId()).isEqualTo("clientId");
		assertThat(mockUser.nameTokenClaim()).isEqualTo("sub");
		assertThat(mockUser.setupBefore()).isEqualByComparingTo(TestExecutionEvent.TEST_METHOD);

		WithSecurityContext context = AnnotatedElementUtils.findMergedAnnotation(Annotated.class,
				WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcUser
	private class Annotated {
	}

	@Test
	public void findMergedAnnotationWhenSetupExplicitThenOverridden() {
		WithSecurityContext context = AnnotatedElementUtils
				.findMergedAnnotation(SetupExplicit.class,
						WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcUser(setupBefore = TestExecutionEvent.TEST_METHOD)
	private class SetupExplicit {
	}

	@Test
	public void findMergedAnnotationWhenSetupOverriddenThenOverridden() {
		WithSecurityContext context = AnnotatedElementUtils.findMergedAnnotation(SetupOverridden.class,
				WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_EXECUTION);
	}

	@WithMockOidcUser(setupBefore = TestExecutionEvent.TEST_EXECUTION)
	private class SetupOverridden {
	}
}
