package org.springframework.security.web.firewall;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.*;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Luke Taylor
 */
public class FirewalledResponseTests {

    @Test
    public void rejectsRedirectLocationContaingCRLF() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FirewalledResponse fwResponse  = new FirewalledResponse(response);

        fwResponse.sendRedirect("/theURL");
        assertEquals("/theURL", response.getRedirectedUrl());

        try {
            fwResponse.sendRedirect("/theURL\r\nsomething");
            fail();
        } catch (IllegalArgumentException expected) {
        }
        try {
            fwResponse.sendRedirect("/theURL\rsomething");
            fail();
        } catch (IllegalArgumentException expected) {
        }

        try {
            fwResponse.sendRedirect("/theURL\nsomething");
            fail();
        } catch (IllegalArgumentException expected) {
        }
    }
}
