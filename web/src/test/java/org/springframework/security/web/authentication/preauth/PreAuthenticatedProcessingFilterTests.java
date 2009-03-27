package org.springframework.security.web.authentication.preauth;

import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.MockAuthenticationManager;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.util.FilterChainOrder;

import javax.servlet.http.HttpServletRequest;

import junit.framework.TestCase;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

public class PreAuthenticatedProcessingFilterTests extends TestCase {
    protected void setUp() throws Exception {
        SecurityContextHolder.clearContext();
    }
    
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

    public final void testDoFilterAuthenticated() throws Exception {
        testDoFilter(true);
    }

    public final void testDoFilterUnauthenticated() throws Exception {
        testDoFilter(false);
    }
    
    private final void testDoFilter(boolean grantAccess) throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest();
        MockHttpServletResponse res = new MockHttpServletResponse();
        getFilter(grantAccess).doFilter(req,res,new MockFilterChain());
        assertEquals(grantAccess,null!= SecurityContextHolder.getContext().getAuthentication());
    }
    
    private static final ConcretePreAuthenticatedProcessingFilter getFilter(boolean grantAccess) throws Exception {
        ConcretePreAuthenticatedProcessingFilter filter = new ConcretePreAuthenticatedProcessingFilter();
        filter.setAuthenticationManager(new MockAuthenticationManager(grantAccess));
        filter.afterPropertiesSet();
        return filter;
    }
    
    private static final class ConcretePreAuthenticatedProcessingFilter extends AbstractPreAuthenticatedProcessingFilter {
        protected Object getPreAuthenticatedPrincipal(HttpServletRequest httpRequest) {
            return "testPrincipal";
        }
        protected Object getPreAuthenticatedCredentials(HttpServletRequest httpRequest) {
            return "testCredentials";
        }

        public int getOrder() {
            return FilterChainOrder.PRE_AUTH_FILTER;
        }
    }
}
