package org.acegisecurity.ui.x509;

import junit.framework.TestCase;

import org.acegisecurity.BadCredentialsException;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.http.HttpServletResponse;


/**
 * Tests {@link X509ProcessingFilterEntryPoint}.
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509ProcessingFilterEntryPointTests extends TestCase {
    //~ Constructors ===========================================================

    public X509ProcessingFilterEntryPointTests() {
        super();
    }

    public X509ProcessingFilterEntryPointTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        X509ProcessingFilterEntryPoint entryPoint = new X509ProcessingFilterEntryPoint();

        entryPoint.commence(request, response, new BadCredentialsException("As thrown by security enforcement filter"));
        assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());

    }
}
