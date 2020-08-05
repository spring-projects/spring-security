/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link ForwardLogoutSuccessHandler}.
 *
 * @author Vedran Pavic
 */
public class ForwardLogoutSuccessHandlerTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void invalidTargetUrl() {
		String targetUrl = "not.valid";

		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("'" + targetUrl + "' is not a valid target URL");

		new ForwardLogoutSuccessHandler(targetUrl);
	}

	@Test
	public void emptyTargetUrl() {
		String targetUrl = " ";

		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("'" + targetUrl + "' is not a valid target URL");

		new ForwardLogoutSuccessHandler(targetUrl);
	}

	@Test
	public void logoutSuccessIsHandled() throws Exception {
		String targetUrl = "/login?logout";
		ForwardLogoutSuccessHandler handler = new ForwardLogoutSuccessHandler(targetUrl);

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		Authentication authentication = mock(Authentication.class);

		handler.onLogoutSuccess(request, response, authentication);

		assertThat(response.getForwardedUrl()).isEqualTo(targetUrl);
	}

}
