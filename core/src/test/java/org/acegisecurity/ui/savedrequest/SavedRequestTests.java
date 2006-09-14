package org.acegisecurity.ui.savedrequest;

import junit.framework.TestCase;
import org.acegisecurity.MockPortResolver;
import org.springframework.mock.web.MockHttpServletRequest;

public class SavedRequestTests extends TestCase {

    public void testCaseInsensitveHeaders() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("USER-aGenT", "Mozilla");
        SavedRequest saved = new SavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Mozilla", saved.getHeaderValues("user-agent").next());
    }

    public void testCaseInsensitveParameters() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("ThisIsATest", "Hi mom");
        SavedRequest saved = new SavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Hi mom", saved.getParameterValues("thisisatest")[0]);
    }
}
