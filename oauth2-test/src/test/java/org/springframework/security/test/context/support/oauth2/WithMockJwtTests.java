/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.context.support.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.test.context.support.TestExecutionEvent;
import org.springframework.security.test.context.support.WithSecurityContext;
import org.springframework.security.test.context.support.WithUserDetails;
import org.springframework.security.test.context.support.oauth2.properties.Property;

public class WithMockJwtTests {

	@Test
	public void defaults() {
		final WithMockJwt auth = AnnotationUtils.findAnnotation(Annotated.class,
				WithMockJwt.class);
		assertThat(auth.name()).isEqualTo(WithMockJwt.DEFAULT_AUTH_NAME);
		assertThat(auth.authorities()).isEmpty();
		assertThat(auth.headers()).hasAtLeastOneElementOfType(Property.class);
		assertThat(auth.claims()).isNotNull();

		final WithSecurityContext context = AnnotatedElementUtils
				.findMergedAnnotation(Annotated.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithMockJwt
	private static class Annotated {
	}

	@Test
	public void findMergedAnnotationWhenSetupExplicitThenOverridden() {
		final WithSecurityContext context = AnnotatedElementUtils
				.findMergedAnnotation(SetupExplicit.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_METHOD);
	}

	@WithUserDetails(setupBefore = TestExecutionEvent.TEST_METHOD)
	private class SetupExplicit {
	}

	@Test
	public void findMergedAnnotationWhenSetupOverriddenThenOverridden() {
		final WithSecurityContext context = AnnotatedElementUtils
				.findMergedAnnotation(SetupOverridden.class, WithSecurityContext.class);

		assertThat(context.setupBefore()).isEqualTo(TestExecutionEvent.TEST_EXECUTION);
	}

	@WithMockJwt(setupBefore = TestExecutionEvent.TEST_EXECUTION)
	private class SetupOverridden {
	}

	@Test
	public void custom() {
		final WithMockJwt auth = AnnotationUtils.findAnnotation(Custom.class,
				WithMockJwt.class);
		assertThat(auth.name()).isEqualTo("truc");
		assertThat(auth.authorities()).hasSize(2);
		assertThat(auth.authorities()).contains("machin", "chose");
		assertThat(auth.headers()).hasSize(1);
		assertThat(auth.headers()[0].name()).isEqualTo("a");
		assertThat(auth.headers()[0].value()).isEqualTo("1");
		assertThat(auth.claims()).isNotNull();
	}

	@WithMockJwt(name = "truc", authorities = { "machin", "chose" }, headers = {
			@Property(name = "a", value = "1") }, claims = {
					@Property(name = "audience", value = "test audience", parser = "org.springframework.security.test.context.support.oauth2.properties.StringListPropertyParser"),
					@Property(name = "issuer", value = "https://test-issuer.org", parser = "org.springframework.security.test.context.support.oauth2.properties.UrlPropertyParser"),
					@Property(name = "issuedAt", value = "2019-03-03T22:35:00.0", parser = "org.springframework.security.test.context.support.oauth2.properties.InstantPropertyParser"),
					@Property(name = "expiresAt", value = "2019-03-04T22:35:00.0", parser = "org.springframework.security.test.context.support.oauth2.properties.InstantPropertyParser"),
					@Property(name = "notBefore", value = "2019-03-03T22:36:00.0", parser = "org.springframework.security.test.context.support.oauth2.properties.InstantPropertyParser"),
					@Property(name = "jti", value = "test ID") })
	private static class Custom {
	}
}
