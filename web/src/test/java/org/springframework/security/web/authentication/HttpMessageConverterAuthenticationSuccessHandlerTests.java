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

package org.springframework.security.web.authentication;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.skyscreamer.jsonassert.JSONAssert;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SimpleSavedRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.verify;

@ExtendWith(MockitoExtension.class)
class HttpMessageConverterAuthenticationSuccessHandlerTests {

	@Mock
	private HttpMessageConverter converter;

	@Mock
	private RequestCache requestCache;

	private HttpMessageConverterAuthenticationSuccessHandler handler = new HttpMessageConverterAuthenticationSuccessHandler();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private Authentication authentication = new TestingAuthenticationToken("user", "password", "ROLE_USER");

	@Test
	void setConverterWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setConverter(null));
	}

	@Test
	void setRequestCacheWhenNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.handler.setRequestCache(null));
	}

	@Test
	void onAuthenticationSuccessWhenDefaultsThenContextRoot() throws Exception {
		this.handler.onAuthenticationSuccess(this.request, this.response, this.authentication);
		String body = this.response.getContentAsString();
		JSONAssert.assertEquals("""
				{
					"redirectUrl" : "/",
					"authenticated": true
				}""", body, false);
	}

	@Test
	void onAuthenticationSuccessWhenSavedRequestThenInResponse() throws Exception {
		SimpleSavedRequest savedRequest = new SimpleSavedRequest("/redirect");
		given(this.requestCache.getRequest(this.request, this.response)).willReturn(savedRequest);
		this.handler.setRequestCache(this.requestCache);
		this.handler.onAuthenticationSuccess(this.request, this.response, this.authentication);
		verify(this.requestCache).removeRequest(this.request, this.response);
		String body = this.response.getContentAsString();
		JSONAssert.assertEquals("""
				{
					"redirectUrl" : "/redirect",
					"authenticated": true
				}""", body, false);
	}

	@Test
	void onAuthenticationSuccessWhenCustomConverterThenInResponse() throws Exception {
		SimpleSavedRequest savedRequest = new SimpleSavedRequest("/redirect");
		given(this.requestCache.getRequest(this.request, this.response)).willReturn(savedRequest);
		String expectedBody = "Custom!";
		BDDMockito.doAnswer((invocation) -> {
			this.response.getWriter().write(expectedBody);
			return null;
		}).when(this.converter).write(any(), any(), any());
		this.handler.setRequestCache(this.requestCache);
		this.handler.setConverter(this.converter);
		this.handler.onAuthenticationSuccess(this.request, this.response, this.authentication);
		String body = this.response.getContentAsString();
		assertThat(body).isEqualTo(expectedBody);
	}

}
