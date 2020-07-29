/*
 * Copyright 2002-2018 the original author or authors.
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

import org.junit.Test;

import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;

import static org.assertj.core.api.Assertions.assertThat;

public class WithUserDetailsTests {

	@Test
	public void defaults() {
		WithUserDetails userDetails = AnnotationUtils.findAnnotation(Annotated.class, WithUserDetails.class);
		assertThat(userDetails.value()).isEqualTo("user");

		WithSecurityContext context = AnnotatedElementUtils.findMergedAnnotation(Annotated.class,
				WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@Test
	public void findMergedAnnotationWhenSetupExplicitThenOverridden() {
		WithSecurityContext context = AnnotatedElementUtils.findMergedAnnotation(SetupExplicit.class,
				WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@Test
	public void findMergedAnnotationWhenSetupOverriddenThenOverridden() {
		WithSecurityContext context = AnnotatedElementUtils.findMergedAnnotation(SetupOverridden.class,
				WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_EXECUTION);
	}

	@WithUserDetails
	private static class Annotated {

	}

	@WithUserDetails(setupBefore = TestExecutionEvent.TEST_METHOD)
	private class SetupExplicit {

	}

	@WithUserDetails(setupBefore = TestExecutionEvent.TEST_EXECUTION)
	private class SetupOverridden {

	}

}
