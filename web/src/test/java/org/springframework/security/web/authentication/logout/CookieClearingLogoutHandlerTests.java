/*
 * Copyright 2002-2021 the original author or authors.
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

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 * @author Onur Kagan Ozcan
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
		assertThat(response.getCookies()).hasSize(1);
		for (Cookie c : response.getCookies()) {
			assertThat(c.getPath()).isEqualTo("/");
			assertThat(c.getMaxAge()).isZero();
		}
	}

	@Test
	public void configuredCookiesAreCleared() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/app");
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie", "my_cookie_too");
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies()).hasSize(2);
		for (Cookie c : response.getCookies()) {
			assertThat(c.getPath()).isEqualTo("/app");
			assertThat(c.getMaxAge()).isZero();
		}
	}

	@Test
	public void configuredCookieIsSecure() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSecure(true);
		request.setContextPath("/app");
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie");
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies()).hasSize(1);
		assertThat(response.getCookies()[0].getSecure()).isTrue();
	}

	@Test
	public void configuredCookieIsNotSecure() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setSecure(false);
		request.setContextPath("/app");
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler("my_cookie");
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies()).hasSize(1);
		assertThat(response.getCookies()[0].getSecure()).isFalse();
	}

	@Test
	public void passedInCookiesAreCleared() {
		MockHttpServletResponse response = new MockHttpServletResponse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/foo/bar");
		Cookie cookie1 = new Cookie("my_cookie", null);
		cookie1.setPath("/foo");
		cookie1.setMaxAge(0);
		Cookie cookie2 = new Cookie("my_cookie_too", null);
		cookie2.setPath("/foo");
		cookie2.setMaxAge(0);
		CookieClearingLogoutHandler handler = new CookieClearingLogoutHandler(cookie1, cookie2);
		handler.logout(request, response, mock(Authentication.class));
		assertThat(response.getCookies()).hasSize(2);
		for (Cookie c : response.getCookies()) {
			assertThat(c.getPath()).isEqualTo("/foo");
			assertThat(c.getMaxAge()).isZero();
		}
	}

	@Test
	public void invalidAge() {
		Cookie cookie1 = new Cookie("my_cookie", null);
		cookie1.setPath("/foo");
		cookie1.setMaxAge(100);
		assertThatIllegalArgumentException().isThrownBy(() -> new CookieClearingLogoutHandler(cookie1));
	}

}
