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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.predicate.RuntimeHintsPredicates;
import org.springframework.core.io.support.SpringFactoriesLoader;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.test.context.aot.TestRuntimeHintsRegistrar;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link WebTestUtilsTestRuntimeHints}.
 *
 * @author Marcus da Coregio
 */
class WebTestUtilsTestRuntimeHintsTests {

	private final RuntimeHints hints = new RuntimeHints();

	@BeforeEach
	void setup() {
		SpringFactoriesLoader.forResourceLocation("META-INF/spring/aot.factories").load(TestRuntimeHintsRegistrar.class)
				.forEach((registrar) -> registrar.registerHints(this.hints, WebTestUtilsTestRuntimeHintsTests.class,
						ClassUtils.getDefaultClassLoader()));
	}

	@Test
	void filterChainProxyHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(FilterChainProxy.class)
				.withMemberCategories(MemberCategory.INVOKE_DECLARED_METHODS)).accepts(this.hints);
	}

	@Test
	void csrfFilterHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(CsrfFilter.class)
				.withMemberCategories(MemberCategory.DECLARED_FIELDS)).accepts(this.hints);
	}

	@Test
	void securityContextPersistenceFilterHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(SecurityContextPersistenceFilter.class)
				.withMemberCategories(MemberCategory.DECLARED_FIELDS)).accepts(this.hints);
	}

	@Test
	void securityContextHolderFilterHasHints() {
		assertThat(RuntimeHintsPredicates.reflection().onType(SecurityContextHolderFilter.class)
				.withMemberCategories(MemberCategory.DECLARED_FIELDS)).accepts(this.hints);
	}

}
