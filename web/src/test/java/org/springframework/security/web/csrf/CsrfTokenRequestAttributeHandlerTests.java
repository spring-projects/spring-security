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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.springframework.security.web.csrf.CsrfTokenAssert.assertThatCsrfToken;

/**
 * Tests for {@link CsrfTokenRequestAttributeHandler}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class CsrfTokenRequestAttributeHandlerTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private CsrfToken token;

	private CsrfTokenRequestAttributeHandler handler;

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.token = new DefaultCsrfToken("headerName", "paramName", "csrfTokenValue");
		this.handler = new CsrfTokenRequestAttributeHandler();
	}

	@Test
	public void handleWhenRequestIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.handler.handle(null, this.response, () -> this.token))
				.withMessage("request cannot be null");
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
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.handle(this.request, this.response, null))
				.withMessage("deferredCsrfToken cannot be null");
	}

	@Test
	public void handleWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		this.handler.setCsrfRequestAttributeName(null);
		assertThatIllegalStateException()
				.isThrownBy(() -> this.handler.handle(this.request, this.response, () -> null))
				.withMessage("csrfTokenSupplier returned null delegate");
		// @formatter:on
	}

	@Test
	public void handleWhenCsrfRequestAttributeSetThenUsed() {
		this.handler.setCsrfRequestAttributeName("_csrf");
		this.handler.handle(this.request, this.response, () -> this.token);
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);
		assertThatCsrfToken(this.request.getAttribute("_csrf")).isEqualTo(this.token);
	}

	@Test
	public void handleWhenValidParametersThenRequestAttributesSet() {
		this.handler.handle(this.request, this.response, () -> this.token);
		assertThatCsrfToken(this.request.getAttribute(CsrfToken.class.getName())).isEqualTo(this.token);
		assertThatCsrfToken(this.request.getAttribute("_csrf")).isEqualTo(this.token);
	}

	@Test
	public void resolveCsrfTokenValueWhenRequestIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.resolveCsrfTokenValue(null, this.token))
				.withMessage("request cannot be null");
	}

	@Test
	public void resolveCsrfTokenValueWhenCsrfTokenIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.resolveCsrfTokenValue(this.request, null))
				.withMessage("csrfToken cannot be null");
	}

	@Test
	public void resolveCsrfTokenValueWhenTokenNotSetThenReturnsNull() {
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isNull();
	}

	@Test
	public void resolveCsrfTokenValueWhenParameterSetThenReturnsTokenValue() {
		this.request.setParameter(this.token.getParameterName(), this.token.getToken());
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderSetThenReturnsTokenValue() {
		this.request.addHeader(this.token.getHeaderName(), this.token.getToken());
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo(this.token.getToken());
	}

	@Test
	public void resolveCsrfTokenValueWhenHeaderAndParameterSetThenHeaderIsPreferred() {
		this.request.addHeader(this.token.getHeaderName(), "header");
		this.request.setParameter(this.token.getParameterName(), "parameter");
		String tokenValue = this.handler.resolveCsrfTokenValue(this.request, this.token);
		assertThat(tokenValue).isEqualTo("header");
	}

}
