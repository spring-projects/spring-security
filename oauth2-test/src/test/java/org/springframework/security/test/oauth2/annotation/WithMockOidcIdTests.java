/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.annotation;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.oauth2.support.AbstractAuthenticationBuilder;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class WithMockOidcIdTests {

	@Test
	public void defaults() {
		final WithMockOidcIdToken auth = AnnotationUtils.findAnnotation(Annotated.class, WithMockOidcIdToken.class);
		assertThat(auth.authorities()).hasSize(1);
		assertThat(auth.authorities()).contains("ROLE_USER");
		assertThat(auth.authorizationRequest()).isNotNull();
		assertThat(auth.claims()).isEmpty();
		assertThat(auth.clientRegistration()).isNotNull();
		assertThat(auth.name()).isEqualTo(AbstractAuthenticationBuilder.DEFAULT_AUTH_NAME);
		assertThat(auth.nameAttributeKey()).isNotEmpty();
		assertThat(auth.scopes()).isEmpty();

		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(Annotated.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcIdToken
	private static class Annotated {
	}

	@Test
	public void findMergedAnnotationWhenSetupExplicitThenOverridden() {
		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(SetupExplicit.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockOidcIdToken(setupBefore = TestExecutionEvent.TEST_METHOD)
	private class SetupExplicit {
	}

	@Test
	public void findMergedAnnotationWhenSetupOverriddenThenOverridden() {
		final WithSecurityContext context =
				AnnotatedElementUtils.findMergedAnnotation(SetupOverridden.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_EXECUTION);
	}

	@WithMockOidcIdToken(setupBefore = TestExecutionEvent.TEST_EXECUTION)
	private class SetupOverridden {
	}
}
