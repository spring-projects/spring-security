package org.springframework.security.web.authentication.logout;

import static org.assertj.core.api.Assertions.*;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.firewall.DefaultHttpFirewall;

/**
 * @author Luke Taylor
 */
public class LogoutHandlerTests {
	LogoutFilter filter;
	@Before
	public void setUp() throws Exception {
		filter = new LogoutFilter("/success", new SecurityContextLogoutHandler());
	}

	@Test
	public void testRequiresLogoutUrlWorksWithPathParams() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setRequestURI("/context/logout;someparam=blah?param=blah");
		request.setServletPath("/logout;someparam=blah");
		request.setQueryString("otherparam=blah");

		DefaultHttpFirewall fw = new DefaultHttpFirewall();
		assertThat(filter.requiresLogout(fw.getFirewalledRequest(request), response)).isTrue();
	}

	@Test
	public void testRequiresLogoutUrlWorksWithQueryParams() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/context");
		MockHttpServletResponse response = new MockHttpServletResponse();

		request.setServletPath("/logout");
		request.setRequestURI("/context/logout?param=blah");
		request.setQueryString("otherparam=blah");

		assertThat(filter.requiresLogout(request, response)).isTrue();
	}

}
