package org.springframework.security.ui.preauth;

import org.springframework.security.AuthenticationCredentialsNotFoundException;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 *
 * @author TSARDD
 * @since 18-okt-2007
 */
public class PreAuthenticatedProcessingFilterEntryPointTests extends TestCase {

	public void testGetSetOrder() {
		PreAuthenticatedProcessingFilterEntryPoint fep = new PreAuthenticatedProcessingFilterEntryPoint();
		fep.setOrder(333);
		assertEquals(fep.getOrder(), 333);
	}

	public void testCommence() {
		MockHttpServletRequest req = new MockHttpServletRequest();
		MockHttpServletResponse resp = new MockHttpServletResponse();
		PreAuthenticatedProcessingFilterEntryPoint fep = new PreAuthenticatedProcessingFilterEntryPoint();
		try {
			fep.commence(req,resp,new AuthenticationCredentialsNotFoundException("test"));
			assertEquals("Incorrect status",resp.getStatus(),HttpServletResponse.SC_FORBIDDEN);
		} catch (IOException e) {
			fail("Unexpected exception thrown: "+e);
		} catch (ServletException e) {
			fail("Unexpected exception thrown: "+e);
		}

	}
}
