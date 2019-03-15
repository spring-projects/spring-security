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
package org.springframework.security.web.authentication.logout;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

import javax.servlet.http.Cookie;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class CookieClearingLogoutHandlerTests {

	// SEC-2036
	@Test
	public void emptyContextRootIsConverted() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("");
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie");
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies().length).isEqualTo(1);
		for (Cookie c : response.getCookies()) {
			assertThat(c.getPath()).isEqualTo("/");
			assertThat(c.getMaxAge()).isEqualTo(0);
		}
	}

	@Test
	public void configuredCookiesAreCleared() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/app");
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler(
				"my_cookie", "my_cookie_too");
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies().length).isEqualTo(2);
		for (Cookie c : response.getCookies()) {
			assertThat(c.getPath()).isEqualTo("/app");
			assertThat(c.getMaxAge()).isEqualTo(0);
		}
	}
}
