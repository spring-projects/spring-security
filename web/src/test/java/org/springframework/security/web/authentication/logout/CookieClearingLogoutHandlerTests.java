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
