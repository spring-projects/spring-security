/*
 * Copyright 2002-2016 the original author or authors.
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

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlAuthenticationSuccessHandlerTests {
	@Test
	public void defaultTargetUrlIsUsedIfNoOtherInformationSet() throws Exception {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));

		assertThat(response.getRedirectedUrl()).isEqualTo("/");
	}

	// SEC-1428
	@Test
	public void redirectIsNotPerformedIfResponseIsCommitted() throws Exception {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler(
				"/target");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.setCommitted(true);

		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
		assertThat(response.getRedirectedUrl()).isNull();
	}

	/**
	 * SEC-213
	 */
	@Test
	public void targetUrlParameterIsUsedIfPresentAndParameterNameIsSet() throws Exception {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler(
				"/defaultTarget");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		request.setParameter("targetUrl", "/target");

		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
		assertThat(response.getRedirectedUrl()).isEqualTo("/defaultTarget");

		// Try with parameter set
		ash.setTargetUrlParameter("targetUrl");
		response = new MockHttpServletResponse();
		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
		assertThat(response.getRedirectedUrl()).isEqualTo("/target");
	}

	@Test
	public void refererIsUsedIfUseRefererIsSet() throws Exception {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler(
				"/defaultTarget");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		ash.setUseReferer(true);
		request.addHeader("Referer", "https://www.springsource.com/");

		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
		assertThat(response.getRedirectedUrl()).isEqualTo("https://www.springsource.com/");
	}

	/**
	 * SEC-297 fix.
	 */
	@Test
	public void absoluteDefaultTargetUrlDoesNotHaveContextPathPrepended()
			throws Exception {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();
		ash.setDefaultTargetUrl("https://monkeymachine.co.uk/");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		ash.onAuthenticationSuccess(request, response, mock(Authentication.class));

		assertThat(response.getRedirectedUrl()).isEqualTo("https://monkeymachine.co.uk/");
	}

	@Test
	public void setTargetUrlParameterNullTargetUrlParameter() {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();
		ash.setTargetUrlParameter("targetUrl");
		ash.setTargetUrlParameter(null);
		assertThat(ash.getTargetUrlParameter()).isNull();
	}

	@Test
	public void setTargetUrlParameterEmptyTargetUrlParameter() {
		SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler();

		try {
			ash.setTargetUrlParameter("");
			fail("Expected Exception");
		}
		catch (IllegalArgumentException success) {
		}

		try {
			ash.setTargetUrlParameter("   ");
			fail("Expected Exception");
		}
		catch (IllegalArgumentException success) {
		}
	}
}
