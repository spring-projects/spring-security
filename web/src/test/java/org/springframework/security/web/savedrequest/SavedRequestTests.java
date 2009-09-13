package org.springframework.security.web.savedrequest;

import static org.junit.Assert.*;

import org.junit.Test;
import org.springframework.security.MockPortResolver;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 *
 */
public class SavedRequestTests {

    @Test
    public void headersAreCaseInsensitive() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("USER-aGenT", "Mozilla");
        DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Mozilla", saved.getHeaderValues("user-agent").next());
    }

    // TODO: Why are parameters case insensitive. I think this is a mistake
    @Test
    public void parametersAreCaseInsensitive() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addParameter("ThisIsATest", "Hi mom");
        DefaultSavedRequest saved = new DefaultSavedRequest(request, new MockPortResolver(8080, 8443));
        assertEquals("Hi mom", saved.getParameterValues("thisisatest")[0]);
    }
}
