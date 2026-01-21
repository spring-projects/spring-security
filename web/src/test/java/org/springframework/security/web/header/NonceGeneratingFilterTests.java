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

package org.springframework.security.web.header;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.keygen.KeyGenerators;
import org.springframework.security.crypto.keygen.StringKeyGenerator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.then;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

/**
 * @author Ziqin Wang
 * @since 7.l
 */
class NonceGeneratingFilterTests {

	private static final String ATTRIBUTE_NAME = "TEST_NONCE_ATTR";

	private static final int MIN_STRENGTH_IN_BYTE = 16;

	@Test
	void attributeShouldBeAddedAndNonceIsLongEnoughBase64ByDefault() throws Exception {
		HttpServletRequest request = new MockHttpServletRequest();
		HttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = spy(new MockFilterChain());

		Filter filter = new NonceGeneratingFilter(ATTRIBUTE_NAME);
		filter.doFilter(request, response, chain);

		assertThat(request.getAttribute(ATTRIBUTE_NAME)).isInstanceOfSatisfying(String.class,
				(nonce) -> assertThat(nonce).isBase64()
					.hasSizeGreaterThanOrEqualTo((int) Math.ceil(4.0 / 3 * MIN_STRENGTH_IN_BYTE)));
		then(chain).should().doFilter(request, response);
	}

	@Test
	void customNonceGeneratorIsUsed() throws Exception {
		HttpServletRequest request = new MockHttpServletRequest();
		HttpServletResponse response = new MockHttpServletResponse();
		FilterChain chain = new MockFilterChain();
		String nonce = KeyGenerators.string().generateKey();
		StringKeyGenerator nonceGenerator = mock();
		given(nonceGenerator.generateKey()).willReturn(nonce);

		Filter filter = new NonceGeneratingFilter(ATTRIBUTE_NAME, nonceGenerator);
		filter.doFilter(request, response, chain);

		assertThat(request.getAttribute(ATTRIBUTE_NAME)).isSameAs(nonce);
		then(nonceGenerator).should().generateKey();
	}

	@Test
	void illegalConstructorArgumentsAreRejected() {
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingFilter(null))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingFilter(""))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingFilter(null, KeyGenerators.string()))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingFilter("", KeyGenerators.string()))
			.withMessage("AttributeName must not be null or empty");
		assertThatIllegalArgumentException().isThrownBy(() -> new NonceGeneratingFilter(ATTRIBUTE_NAME, null))
			.withMessage("NonceGenerator must not be null");
	}

}
