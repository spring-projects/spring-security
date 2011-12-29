package org.springframework.security.web.session;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;

/**
 *
 * @author Rob Winch
 *
 */
public class HttpSessionDestroyedEventTests {
    private MockHttpSession session;
    private HttpSessionDestroyedEvent destroyedEvent;

    @Before
    public void setUp() {
        session = new MockHttpSession();
        session.setAttribute("notcontext", "notcontext");
        session.setAttribute("null", null);
        session.setAttribute("context", new SecurityContextImpl());
        destroyedEvent = new HttpSessionDestroyedEvent(session);
    }

    // SEC-1870
    @Test
    public void getSecurityContexts() {
        List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
        assertEquals(1,securityContexts.size());
        assertSame(session.getAttribute("context"), securityContexts.get(0));
    }

    @Test
    public void getSecurityContextsMulti() {
        session.setAttribute("another", new SecurityContextImpl());
        List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
        assertEquals(2,securityContexts.size());
    }

    @Test
    public void getSecurityContextsDiffImpl() {
        session.setAttribute("context", mock(SecurityContext.class));
        List<SecurityContext> securityContexts = destroyedEvent.getSecurityContexts();
        assertEquals(1,securityContexts.size());
        assertSame(session.getAttribute("context"), securityContexts.get(0));
    }
}