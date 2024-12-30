/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OneTimeTokenAuthenticationConverter}
 *
 * @author Marcus da Coregio
 */
class OneTimeTokenAuthenticationConverterTests {

	private final OneTimeTokenAuthenticationConverter converter = new OneTimeTokenAuthenticationConverter();

	@Test
	void convertWhenTokenParameterThenReturnOneTimeTokenAuthenticationToken() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("token", "1234");
		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getTokenValue()).isEqualTo("1234");
		assertThat(authentication.getPrincipal()).isNull();
	}

	@Test
	void convertWhenTokenAndUsernameParameterThenReturnOneTimeTokenAuthenticationTokenWithUsername() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("token", "1234");
		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNotNull();
		assertThat(authentication.getTokenValue()).isEqualTo("1234");
	}

	@Test
	void convertWhenOnlyUsernameParameterThenReturnNull() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setParameter("username", "josh");
		OneTimeTokenAuthenticationToken authentication = (OneTimeTokenAuthenticationToken) this.converter
			.convert(request);
		assertThat(authentication).isNull();
	}

	@Test
	void convertWhenNoTokenParameterThenNull() {
		Authentication authentication = this.converter.convert(new MockHttpServletRequest());
		assertThat(authentication).isNull();
	}

}
