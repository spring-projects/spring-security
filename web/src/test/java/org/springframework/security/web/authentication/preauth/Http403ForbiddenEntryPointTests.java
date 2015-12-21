package org.springframework.security.web.authentication.preauth;

import static org.assertj.core.api.Assertions.*;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class Http403ForbiddenEntryPointTests {

	public void testCommence() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		MockHttpServletResponse resp = new MockHttpServletResponse();
		Http403ForbiddenEntryPoint fep = new Http403ForbiddenEntryPoint();
		try {
			fep.commence(req, resp,
					new AuthenticationCredentialsNotFoundException("test"));
			assertThat(resp.getStatus()).withFailMessage("Incorrect status").isEqualTo(
					HttpServletResponse.SC_FORBIDDEN);
		}
		catch (IOException e) {
			fail("Unexpected exception thrown: " + e);
		}
		catch (ServletException e) {
			fail("Unexpected exception thrown: " + e);
		}
	}
}
