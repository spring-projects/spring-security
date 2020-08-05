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
package org.springframework.security.web;

import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class DefaultRedirectStrategyTests {

	@Test
	public void contextRelativeUrlWithContextNameInHostnameIsHandledCorrectly() throws Exception {
		DefaultRedirectStrategy rds = new DefaultRedirectStrategy();
		rds.setContextRelative(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/context");
		MockHttpServletResponse response = new MockHttpServletResponse();

		rds.sendRedirect(request, response, "https://context.blah.com/context/remainder");

		assertThat(response.getRedirectedUrl()).isEqualTo("remainder");
	}

	// SEC-2177
	@Test
	public void contextRelativeUrlWithMultipleSchemesInHostnameIsHandledCorrectly() throws Exception {
		DefaultRedirectStrategy rds = new DefaultRedirectStrategy();
		rds.setContextRelative(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/context");
		MockHttpServletResponse response = new MockHttpServletResponse();

		rds.sendRedirect(request, response, "https://https://context.blah.com/context/remainder");

		assertThat(response.getRedirectedUrl()).isEqualTo("remainder");
	}

	@Test(expected = IllegalArgumentException.class)
	public void contextRelativeShouldThrowExceptionIfURLDoesNotContainContextPath() throws Exception {
		DefaultRedirectStrategy rds = new DefaultRedirectStrategy();
		rds.setContextRelative(true);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/context");
		MockHttpServletResponse response = new MockHttpServletResponse();

		rds.sendRedirect(request, response, "https://redirectme.somewhere.else");
	}

}
