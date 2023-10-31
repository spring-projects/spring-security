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
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link XorCsrfTokenRequestAttributeHandler}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class XorCsrfTokenRequestAttributeHandlerTests {

	private static final byte[] XOR_CSRF_TOKEN_BYTES = new byte[] { 1, 1, 1, 96, 99, 98 };

	private static final String XOR_CSRF_TOKEN_VALUE = Base64.getEncoder().encodeToString(XOR_CSRF_TOKEN_BYTES);

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfToken token;

	private SecureRandom secureRandom;

	private XorCsrfTokenRequestAttributeHandler handler;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.token = new DefaultCsrfToken("headerName", "paramName", "abc");
		this.secureRandom = mock(SecureRandom.class);
		this.handler = new XorCsrfTokenRequestAttributeHandler();
	}

	@Test
	public void setSecureRandomWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.setSecureRandom(null))
				.withMessage("secureRandom cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenRequestIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(null, this.response, () -> this.token))
				.withMessage("request cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenResponseIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(this.request, null, () -> this.token))
				.withMessage("response cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenCsrfTokenSupplierIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(this.request, this.response, null))
				.withMessage("deferredCsrfToken cannot be null");
		// @formatter:on
	}

	@Test
	public void handleWhenCsrfTokenIsNullThenThrowsIllegalStateException() {
		this.handler.handle(this.request, this.response, () -> null);
		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute("_csrf");
		// @formatter:off
		assertThatIllegalStateException()
				.isThrownBy(csrfTokenAttribute::getToken)
				.withMessage("csrfToken supplier returned null");
		// @formatter:on
	}

	@Test
	public void handleWhenCsrfRequestAttributeSetThenUsed() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.handler.setSecureRandom(this.secureRandom);
		this.handler.setCsrfRequestAttributeName("_csrf");
		this.handler.handle(this.request, this.response, () -> this.token);
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.request.getAttribute("_csrf")).isNotNull();

		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute("_csrf");
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE);
	}

	@Test
	public void handleWhenSecureRandomSetThenUsed() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.handler.setSecureRandom(this.secureRandom);
		this.handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE);
		verify(this.secureRandom).nextBytes(anyByteArray());
		verifyNoMoreInteractions(this.secureRandom);
	}

	@Test
	public void handleWhenValidParametersThenRequestAttributesSet() {
		willAnswer(fillByteArray()).given(this.secureRandom).nextBytes(anyByteArray());

		this.handler.setSecureRandom(this.secureRandom);
		this.handler.handle(this.request, this.response, () -> this.token);
		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(XOR_CSRF_TOKEN_VALUE);
		verify(this.secureRandom).nextBytes(anyByteArray());
		assertThat(this.request.getAttribute(CsrfToken.class.getName())).isNotNull();
		assertThat(this.request.getAttribute("_csrf")).isNotNull();
	}

	@Test
	public void handleWhenCsrfTokenRequestedTwiceThenCached() {
		this.handler.handle(this.request, this.response, () -> this.token);

		CsrfToken csrfTokenAttribute = (CsrfToken) this.request.getAttribute(CsrfToken.class.getName());
		assertThat(csrfTokenAttribute.getToken()).isNotEqualTo(this.token.getToken());
		assertThat(csrfTokenAttribute.getToken()).isEqualTo(csrfTokenAttribute.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenRequestIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.resolveCsrfTokenValue(null, this.token))
				.withMessage("request cannot be null");
		// @formatter:on
	}

	@Test
	public void resolveCsrfTokenValueWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.resolveCsrfTokenValue(this.request, null))
				.withMessage("csrfToken cannot be null");
		// @formatter:on
	}

	@Test
	public void resolveCsrfTokenValueWhenTokenNotSetThenReturnsNull() {
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isNull();
	}

	@Test
	public void resolveCsrfTokenValueWhenParameterSetThenReturnsTokenValue() {
		this.request.setParameter(this.token.getParameterName(), XOR_CSRF_TOKEN_VALUE);
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderSetThenReturnsTokenValue() {
		this.request.addHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderAndParameterSetThenHeaderIsPreferred() {
		this.request.addHeader(this.token.getHeaderName(), XOR_CSRF_TOKEN_VALUE);
		this.request.setParameter(this.token.getParameterName(), "invalid");
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
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
