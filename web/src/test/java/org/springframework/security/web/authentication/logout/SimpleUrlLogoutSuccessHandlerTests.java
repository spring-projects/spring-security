package org.springframework.security.web.authentication.logout;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlLogoutSuccessHandlerTests {

	@Test
	public void doesntRedirectIfResponseIsCommitted() throws Exception {
		SimpleUrlLogoutSuccessHandler lsh = new SimpleUrlLogoutSuccessHandler();
		lsh.setDefaultTargetUrl("/target");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.setCommitted(true);
		lsh.onLogoutSuccess(request, response, mock(Authentication.class));
		assertThat(request.getSession(false)).isNull();
		assertThat(response.getRedirectedUrl()).isNull();
		assertThat(response.getForwardedUrl()).isNull();
	}

	@Test
	public void absoluteUrlIsSupported() throws Exception {
		SimpleUrlLogoutSuccessHandler lsh = new SimpleUrlLogoutSuccessHandler();
		lsh.setDefaultTargetUrl("http://someurl.com/");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		lsh.onLogoutSuccess(request, response, mock(Authentication.class));
		assertThat(response.getRedirectedUrl()).isEqualTo("http://someurl.com/");
	}

}
