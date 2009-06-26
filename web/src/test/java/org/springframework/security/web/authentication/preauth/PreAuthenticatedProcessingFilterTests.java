package org.springframework.security.web.authentication.preauth;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class PreAuthenticatedProcessingFilterTests {
    @After
    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testAfterPropertiesSet() {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        try {
            filter.afterPropertiesSet();
            fail("AfterPropertiesSet didn't throw expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("AfterPropertiesSet throws unexpected exception");
        }
    }

    @Test
    public void testDoFilterAuthenticated() throws Exception {
        testDoFilter(true);
    }

    @Test
    public void testDoFilterUnauthenticated() throws Exception {
        testDoFilter(false);
    }

    private void testDoFilter(boolean grantAccess) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        getFilter(grantAccess).doFilter(req,res,new MockFilterChain());
        assertEquals(grantAccess,null!= SecurityContextHolder.getContext().getAuthentication());
    }

    private static ConcretePreAuthenticatedProcessingFilter getFilter(boolean grantAccess) throws Exception {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        AuthenticationManager am = mock(AuthenticationManager.class);

        if (!grantAccess) {
            when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException(""));
        } else {
            when(am.authenticate(any(Authentication.class))).thenAnswer(new Answer<Authentication>() {
                public Authentication answer(InvocationOnMock invocation) throws Throwable {
                    return (Authentication) invocation.getArguments()[0];
                }
            });
        }

        filter.setAuthenticationManager(am);
        filter.afterPropertiesSet();
        return filter;
    }

    private static class ConcretePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
        protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
            return "testPrincipal";
        }
        protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
            return "testCredentials";
        }
    }
}
