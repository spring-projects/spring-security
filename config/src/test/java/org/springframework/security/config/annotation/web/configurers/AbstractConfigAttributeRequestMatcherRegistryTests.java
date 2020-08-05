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

package org.springframework.security.config.annotation.web.configurers;

import java.util.List;

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RegexRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;

public class AbstractConfigAttributeRequestMatcherRegistryTests {

	private ConcreteAbstractRequestMatcherMappingConfigurer registry;

	@Before
	public void setup() {
		registry = new ConcreteAbstractRequestMatcherMappingConfigurer();
	}

	@Test
	public void testGetRequestMatcherIsTypeRegexMatcher() {
		List<RequestMatcher> requestMatchers = registry.regexMatchers(HttpMethod.GET, "/a.*");

		for (RequestMatcher requestMatcher : requestMatchers) {
			assertThat(requestMatcher).isInstanceOf(RegexRequestMatcher.class);
		}
	}

	@Test
	public void testRequestMatcherIsTypeRegexMatcher() {
		List<RequestMatcher> requestMatchers = registry.regexMatchers("/a.*");

		for (RequestMatcher requestMatcher : requestMatchers) {
			assertThat(requestMatcher).isInstanceOf(RegexRequestMatcher.class);
		}
	}

	@Test
	public void testGetRequestMatcherIsTypeAntPathRequestMatcher() {
		List<RequestMatcher> requestMatchers = registry.antMatchers(HttpMethod.GET, "/a.*");

		for (RequestMatcher requestMatcher : requestMatchers) {
			assertThat(requestMatcher).isInstanceOf(AntPathRequestMatcher.class);
		}
	}

	@Test
	public void testRequestMatcherIsTypeAntPathRequestMatcher() {
		List<RequestMatcher> requestMatchers = registry.antMatchers("/a.*");

		for (RequestMatcher requestMatcher : requestMatchers) {
			assertThat(requestMatcher).isInstanceOf(AntPathRequestMatcher.class);
		}
	}

	static class ConcreteAbstractRequestMatcherMappingConfigurer
			extends AbstractConfigAttributeRequestMatcherRegistry<List<RequestMatcher>> {

		List<AccessDecisionVoter> decisionVoters() {
			return null;
		}

		protected List<RequestMatcher> chainRequestMatchersInternal(List<RequestMatcher> requestMatchers) {
			return requestMatchers;
		}

		public List<RequestMatcher> mvcMatchers(String... mvcPatterns) {
			return null;
		}

		public List<RequestMatcher> mvcMatchers(HttpMethod method, String... mvcPatterns) {
			return null;
		}

	}

}
