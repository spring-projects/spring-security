/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.cas.web;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link CasGatewayResolverRequestMatcher}.
 *
 * @author Marcus da Coregio
 */
class CasGatewayResolverRequestMatcherTests {

	CasGatewayResolverRequestMatcher matcher = new CasGatewayResolverRequestMatcher(new ServiceProperties());

	@Test
	void constructorWhenServicePropertiesNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new CasGatewayResolverRequestMatcher(null))
			.withMessage("serviceProperties cannot be null");
	}

	@Test
	void matchesWhenAlreadyGatewayedThenReturnsFalse() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession().setAttribute("_const_cas_gateway_", "yes");
		boolean matches = this.matcher.matches(request);
		assertThat(matches).isFalse();
	}

	@Test
	void matchesWhenNotGatewayedThenReturnsTrue() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		boolean matches = this.matcher.matches(request);
		assertThat(matches).isTrue();
	}

	@Test
	void matchesWhenNoSessionThenReturnsTrue() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSession(null);
		boolean matches = this.matcher.matches(request);
		assertThat(matches).isTrue();
	}

	@Test
	void matchesWhenNotGatewayedAndCheckedAgainThenSavesAsGatewayedAndReturnsFalse() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		boolean matches = this.matcher.matches(request);
		boolean secondMatch = this.matcher.matches(request);
		assertThat(matches).isTrue();
		assertThat(secondMatch).isFalse();
	}

}
