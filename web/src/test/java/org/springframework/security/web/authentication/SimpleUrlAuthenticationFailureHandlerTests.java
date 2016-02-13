package org.springframework.security.web.authentication;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.mock;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlAuthenticationFailureHandlerTests {

	@Test
	public void error401IsReturnedIfNoUrlIsSet() throws Exception {
		SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler();
		RedirectStrategy rs = mock(RedirectStrategy.class);
		afh.setRedirectStrategy(rs);
		assertThat(afh.getRedirectStrategy()).isSameAs(rs);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		afh.onAuthenticationFailure(request, response,
				mock(AuthenticationException.class));
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void exceptionIsSavedToSessionOnRedirect() throws Exception {
		SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler();
		afh.setDefaultFailureUrl("/target");
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		AuthenticationException e = mock(AuthenticationException.class);

		afh.onAuthenticationFailure(request, response, e);
		assertThat(request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).isSameAs(e);
		assertThat(response.getRedirectedUrl()).isEqualTo("/target");
	}

	@Test
	public void exceptionIsNotSavedIfAllowSessionCreationIsFalse() throws Exception {
		SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler(
				"/target");
		afh.setAllowSessionCreation(false);
		assertThat(afh.isAllowSessionCreation()).isFalse();
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();

		afh.onAuthenticationFailure(request, response,
				mock(AuthenticationException.class));
		assertThat(request.getSession(false)).isNull();
	}

	// SEC-462
	@Test
	public void responseIsForwardedIfUseForwardIsTrue() throws Exception {
		SimpleUrlAuthenticationFailureHandler afh = new SimpleUrlAuthenticationFailureHandler(
				"/target");
		afh.setUseForward(true);
		assertThat(afh.isUseForward()).isTrue();

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		AuthenticationException e = mock(AuthenticationException.class);

		afh.onAuthenticationFailure(request, response, e);
		assertThat(request.getSession(false)).isNull();
		assertThat(response.getRedirectedUrl()).isNull();
		assertThat(response.getForwardedUrl()).isEqualTo("/target");
		// Request scope should be used for forward
		assertThat(request.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION)).isSameAs(e);
	}

}
