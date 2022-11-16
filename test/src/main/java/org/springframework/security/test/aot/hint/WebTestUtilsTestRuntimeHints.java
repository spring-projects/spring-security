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

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.test.context.aot.TestRuntimeHintsRegistrar;

/**
 * {@link TestRuntimeHintsRegistrar} implementation that register runtime hints for
 * {@link org.springframework.security.test.web.support.WebTestUtils}.
 *
 * @author Marcus da Coregio
 * @since 6.0
 */
class WebTestUtilsTestRuntimeHints implements TestRuntimeHintsRegistrar {

	@Override
	public void registerHints(RuntimeHints hints, Class<?> testClass, ClassLoader classLoader) {
		registerFilterChainProxyHints(hints);
		registerSecurityContextRepositoryHints(hints);
		registerCsrfTokenRepositoryHints(hints);
	}

	private void registerFilterChainProxyHints(RuntimeHints hints) {
		hints.reflection().registerType(FilterChainProxy.class, MemberCategory.INVOKE_DECLARED_METHODS);
	}

	private void registerCsrfTokenRepositoryHints(RuntimeHints hints) {
		hints.reflection().registerType(CsrfFilter.class, MemberCategory.DECLARED_FIELDS);
	}

	private void registerSecurityContextRepositoryHints(RuntimeHints hints) {
		hints.reflection().registerType(SecurityContextPersistenceFilter.class, MemberCategory.DECLARED_FIELDS);
		hints.reflection().registerType(SecurityContextHolderFilter.class, MemberCategory.DECLARED_FIELDS);
	}

}
