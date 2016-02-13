package org.springframework.security.web.firewall;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Luke Taylor
 */
public class FirewalledResponseTests {

	@Test
	public void rejectsRedirectLocationContaingCRLF() throws Exception {
		MockHttpServletResponse response = new MockHttpServletResponse();
		FirewalledResponse fwResponse = new FirewalledResponse(response);

		fwResponse.sendRedirect("/theURL");
		assertThat(response.getRedirectedUrl()).isEqualTo("/theURL");

		try {
			fwResponse.sendRedirect("/theURL\r\nsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
		try {
			fwResponse.sendRedirect("/theURL\rsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}

		try {
			fwResponse.sendRedirect("/theURL\nsomething");
			fail("IllegalArgumentException should have thrown");
		}
		catch (IllegalArgumentException expected) {
		}
	}
}
