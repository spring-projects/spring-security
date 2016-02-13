package org.springframework.security.integration;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import javax.servlet.http.HttpSession;

@ContextConfiguration(locations = { "/http-path-param-stripping-app-context.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
public class HttpPathParameterStrippingTests {

	@Autowired
	private FilterChainProxy fcp;

	@Test
	public void securedFilterChainCannotBeBypassedByAddingPathParameters()
			throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setPathInfo("/secured;x=y/admin.html");
		request.setSession(createAuthenticatedSession("ROLE_USER"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		fcp.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(403);
	}

	@Test
	public void adminFilePatternCannotBeBypassedByAddingPathParameters() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setServletPath("/secured/admin.html;x=user.html");
		request.setSession(createAuthenticatedSession("ROLE_USER"));
		MockHttpServletResponse response = new MockHttpServletResponse();
		fcp.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(403);

		// Try with pathInfo
		request = new MockHttpServletRequest();
		request.setServletPath("/secured");
		request.setPathInfo("/admin.html;x=user.html");
		request.setSession(createAuthenticatedSession("ROLE_USER"));
		response = new MockHttpServletResponse();
		fcp.doFilter(request, response, new MockFilterChain());
		assertThat(response.getStatus()).isEqualTo(403);
	}

	public HttpSession createAuthenticatedSession(String... roles) {
		MockHttpSession session = new MockHttpSession();
		SecurityContextHolder.getContext().setAuthentication(
				new TestingAuthenticationToken("bob", "bobspassword", roles));
		session.setAttribute(
				HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
				SecurityContextHolder.getContext());
		SecurityContextHolder.clearContext();
		return session;
	}

}
