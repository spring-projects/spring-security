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

package org.springframework.security.web.csrf;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link XorCsrfTokenRequestProcessor}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class XorCsrfTokenRequestProcessorTests {

	private static final byte[] XOR_CSRF_TOKEN_BYTES = new byte[] { 1, 1, 1, 96, 99, 98 };

	private static final String XOR_CSRF_TOKEN_VALUE = Base64.getEncoder().encodeToString(XOR_CSRF_TOKEN_BYTES);

	private MockHttpServletRequest request;

	private CsrfToken token;

	private SecureRandom secureRandom;

	private XorCsrfTokenRequestProcessor processor;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.token = new DefaultCsrfToken("headerName", "paramName", "abc");
		this.secureRandom = mock(SecureRandom.class);
		this.processor = new XorCsrfTokenRequestProcessor();
	}

	@Test
	public void handleWhenRequestIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.processor.handle(null, this.token))
				.withMessage("request cannot be null");
	}

	@Test
	public void handleWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.processor.handle(this.request, null))
				.withMessage("csrfToken cannot be null");
	}

	@Test
	public void handleWhenCsrfRequestAttributeSetThenUsed() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.processor.setSecureRandom(this.secureRandom);
		this.processor.setCsrfRequestAttributeName("_csrf");
		this.processor.handle(this.request, this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.request.getAttribute("_csrf")).isNotNull();

		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute("_csrf");
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE);
	}

	@Test
	public void handleWhenSecureRandomSetThenUsed() {
		this.processor.setSecureRandom(this.secureRandom);
		this.processor.handle(this.request, this.token);
		verify(this.secureRandom).nextBytes(anyByteArray());
		verifyNoMoreInteractions(this.secureRandom);
	}

	@Test
	public void handleWhenValidParametersThenRequestAttributesSet() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.processor.setSecureRandom(this.secureRandom);
		this.processor.handle(this.request, this.token);
		verify(this.secureRandom).nextBytes(anyByteArray());
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.request.getAttribute(this.token.getParameterName())).isNotNull();

		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE);
	}

	@Test
	public void resolveCsrfTokenValueWhenRequestIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.processor.resolveCsrfTokenValue(null, this.token))
				.withMessage("request cannot be null");
	}

	@Test
	public void resolveCsrfTokenValueWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.processor.resolveCsrfTokenValue(this.request, null))
				.withMessage("csrfToken cannot be null");
	}

	@Test
	public void resolveCsrfTokenValueWhenTokenNotSetThenReturnsNull() {
		String tokenValue = this.processor.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isNull();
	}

	@Test
	public void resolveCsrfTokenValueWhenParameterSetThenReturnsTokenValue() {
		this.request.setParameter(this.token.getParameterName(), XOR_CSRF_TOKEN_VALUE);
		String tokenValue = this.processor.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderSetThenReturnsTokenValue() {
		this.request.addHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		String tokenValue = this.processor.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderAndParameterSetThenHeaderIsPreferred() {
		this.request.addHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		this.request.setParameter(this.token.getParameterName(), "invalid");
		String tokenValue = this.processor.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	private static Answer<Void> fillByteArray() {
		return (invocation) -> {
			byte[] bytes = invocation.getArgument(0);
			Arrays.fill(bytes, (byte) 1);
			return null;
		};
	}

	private static byte[] anyByteArray() {
		return any(byte[].class);
	}

}
