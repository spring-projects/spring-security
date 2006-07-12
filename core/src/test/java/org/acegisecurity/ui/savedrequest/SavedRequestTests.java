package org.acegisecurity.ui.savedrequest;

import junit.framework.TestCase;
import org.acegisecurity.MockPortResolver;
import org.springframework.mock.web.MockHttpServletRequest;

public class SavedRequestTests extends TestCase {

    public void testCaseInsensitve() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("USER-aGenT", "Mozilla");
        SavedRequest saved = new SavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Mozilla", saved.getHeaderValues("user-agent").next());
    }

}
