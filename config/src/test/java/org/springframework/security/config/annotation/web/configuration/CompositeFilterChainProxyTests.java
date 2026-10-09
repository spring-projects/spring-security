/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import java.util.List;

import jakarta.servlet.Filter;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regression tests for the reflective {@code getFilters(HttpServletRequest)} contract
 * that {@code WebTestUtils.findFilter} relies on when invoked against a
 * {@link WebSecurityConfiguration.CompositeFilterChainProxy}.
 */
class CompositeFilterChainProxyTests {

	@Test
	void getFiltersWhenCompositeFilterChainProxyThenResolvesFilters() {
		CsrfFilter sentinel = new CsrfFilter(new HttpSessionCsrfTokenRepository());
		DefaultSecurityFilterChain inner = new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE, sentinel);
		FilterChainProxy innerProxy = new FilterChainProxy(inner);
		WebSecurityConfiguration.CompositeFilterChainProxy composite = new WebSecurityConfiguration.CompositeFilterChainProxy(
				List.<Filter>of(innerProxy));

		MockHttpServletRequest request = new MockHttpServletRequest();

		// Mirrors the exact reflective call WebTestUtils.findFilter makes at WebTestUtils.java:158.
		// We invoke getFilters directly rather than via WebTestUtils.findFilter because that method
		// is package-private and the CompositeFilterChainProxy class lives in a different package.
		List<Filter> filters = ReflectionTestUtils.invokeMethod(composite, "getFilters", request);

		assertThat(filters).contains(sentinel);
	}

}
