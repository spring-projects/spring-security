package org.springframework.security.web.authentication;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

/**
 *
 * @author Luke Taylor
 */
public class SimpleUrlAuthenticationSuccessHandlerTests {

    // SEC-1428
    @Test
    public void redirectIsNotPerformedIfResponseIsCommitted() throws Exception {
        SimpleUrlAuthenticationSuccessHandler ash = new SimpleUrlAuthenticationSuccessHandler("/target");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setCommitted(true);

        ash.onAuthenticationSuccess(request, response, mock(Authentication.class));
        assertNull(response.getRedirectedUrl());
    }

}
