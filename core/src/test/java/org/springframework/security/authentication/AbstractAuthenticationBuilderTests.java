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

package org.springframework.security.authentication;

import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

import static org.assertj.core.api.Assertions.assertThat;

class AbstractAuthenticationBuilderTests {

	@Test
	void applyWhenAuthoritiesThenAdds() {
		TestingAuthenticationToken factorOne = new TestingAuthenticationToken("user", "pass", "FACTOR_ONE");
		TestingAuthenticationToken factorTwo = new TestingAuthenticationToken("user", "pass", "FACTOR_TWO");
		TestAbstractAuthenticationBuilder builder = new TestAbstractAuthenticationBuilder(factorOne);
		Authentication result = builder.authorities((a) -> a.addAll(factorTwo.getAuthorities())).build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

	@Test
	void authenticationWhenAuthoritiesThenAdds() {
		TestingAuthenticationToken factorOne = new TestingAuthenticationToken("user", "pass", "FACTOR_ONE");
		TestingAuthenticationToken factorTwo = new TestingAuthenticationToken("user", "pass", "FACTOR_TWO");
		TestAbstractAuthenticationBuilder builder = new TestAbstractAuthenticationBuilder(factorOne);
		Authentication result = builder.authentication(factorTwo).build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

	private static final class TestAbstractAuthenticationBuilder
			extends TestingAuthenticationToken.Builder<TestAbstractAuthenticationBuilder> {

		private TestAbstractAuthenticationBuilder(TestingAuthenticationToken token) {
			super(token);
		}

		@Override
		public TestingAuthenticationToken build() {
			return new TestingAuthenticationToken(this);
		}

	}

}
