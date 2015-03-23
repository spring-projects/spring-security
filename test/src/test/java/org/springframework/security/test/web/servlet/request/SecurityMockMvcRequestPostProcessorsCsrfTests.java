/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.test.web.servlet.request;

import static org.fest.assertions.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.powermock.api.mockito.PowerMockito.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareOnlyThisForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.DefaultCsrfToken;

@RunWith(PowerMockRunner.class)
@PrepareOnlyThisForTest(WebTestUtils.class)
public class SecurityMockMvcRequestPostProcessorsCsrfTests {
	@Mock
	private CsrfTokenRepository repository;
	private DefaultCsrfToken token;

	private MockHttpServletRequest request;

	@Before
	public void setup() {
		token = new DefaultCsrfToken("header", "param", "token");
		request = new MockHttpServletRequest();
		mockWebTestUtils();
	}

	@Test
	public void csrfWithParam() {
		MockHttpServletRequest postProcessedRequest = csrf().postProcessRequest(request);

		assertThat(postProcessedRequest.getParameter(token.getParameterName()))
				.isEqualTo(token.getToken());
		assertThat(postProcessedRequest.getHeader(token.getHeaderName())).isNull();
	}

	@Test
	public void csrfWithHeader() {
		MockHttpServletRequest postProcessedRequest = csrf().asHeader()
				.postProcessRequest(request);

		assertThat(postProcessedRequest.getParameter(token.getParameterName())).isNull();
		assertThat(postProcessedRequest.getHeader(token.getHeaderName())).isEqualTo(
				token.getToken());
	}

	@Test
	public void csrfWithInvalidParam() {
		MockHttpServletRequest postProcessedRequest = csrf().useInvalidToken()
				.postProcessRequest(request);

		assertThat(postProcessedRequest.getParameter(token.getParameterName()))
				.isNotEmpty().isNotEqualTo(token.getToken());
		assertThat(postProcessedRequest.getHeader(token.getHeaderName())).isNull();
	}

	@Test
	public void csrfWithInvalidHeader() {
		MockHttpServletRequest postProcessedRequest = csrf().asHeader().useInvalidToken()
				.postProcessRequest(request);

		assertThat(postProcessedRequest.getParameter(token.getParameterName())).isNull();
		assertThat(postProcessedRequest.getHeader(token.getHeaderName())).isNotEmpty()
				.isNotEqualTo(token.getToken());
	}

	private void mockWebTestUtils() {
		spy(WebTestUtils.class);
		when(WebTestUtils.getCsrfTokenRepository(request)).thenReturn(repository);
		when(repository.loadToken(request)).thenReturn(token);
		when(repository.generateToken(request)).thenReturn(token);
	}
}
