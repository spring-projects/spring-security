package org.springframework.security.web.authentication.preauth;

import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

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
        Http403ForbiddenEntryPoint fep = new Http403ForbiddenEntryPoint();
        fep.setOrder(333);
        assertEquals(fep.getOrder(), 333);
    }

    public void testCommence() {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse resp = new MockHttpServletResponse();
        Http403ForbiddenEntryPoint fep = new Http403ForbiddenEntryPoint();
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
