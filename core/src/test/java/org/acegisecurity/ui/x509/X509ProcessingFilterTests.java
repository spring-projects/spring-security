package net.sf.acegisecurity.ui.x509;

import junit.framework.TestCase;

import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.providers.x509.X509TestUtils;
import net.sf.acegisecurity.providers.x509.X509AuthenticationToken;
import net.sf.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import net.sf.acegisecurity.MockHttpServletResponse;
import net.sf.acegisecurity.MockHttpServletRequest;
import net.sf.acegisecurity.MockHttpSession;
import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.AuthenticationManager;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.MockAuthenticationManager;
import net.sf.acegisecurity.ui.AbstractProcessingFilter;
import net.sf.acegisecurity.util.MockFilterChain;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import java.security.cert.X509Certificate;

/**
 * @author Luke Taylor
 */
public class X509ProcessingFilterTests extends TestCase {
    //~ Constructors ===========================================================

    public X509ProcessingFilterTests() {
        super();
    }

    public X509ProcessingFilterTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void tearDown() {
        ContextHolder.setContext(null);
    }

    public void testNeedsAuthenticationManager() throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.afterPropertiesSet();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException failed) {
            // ignored
        }
    }

    public void testDoFilterWithNonHttpServletRequestDetected()
        throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.doFilter(null, new MockHttpServletResponse(),
                new MockFilterChain(false));
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletRequest",
                expected.getMessage());
        }
    }

    public void testDoFilterWithNonHttpServletResponseDetected()
        throws Exception {
        X509ProcessingFilter filter = new X509ProcessingFilter();

        try {
            filter.doFilter(new MockHttpServletRequest(null, null), null,
                new MockFilterChain(false));
            fail("Should have thrown ServletException");
        } catch (ServletException expected) {
            assertEquals("Can only process HttpServletResponse",
                expected.getMessage());
        }
    }


    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(null, new MockHttpSession());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        request.setAttribute("javax.servlet.request.X509Certificate",
                new X509Certificate[] {X509TestUtils.buildTestCertificate()});

        AuthenticationManager authMgr = new MockX509AuthenticationManager();

        ContextHolder.setContext(new SecureContextImpl());

        SecureContext ctx = SecureContextUtils.getSecureContext();

        ctx.setAuthentication(null);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);
        filter.afterPropertiesSet();
        filter.init(null);
        filter.doFilter(request, response, chain);
        filter.destroy();

        Authentication result = ctx.getAuthentication();

        assertNotNull(result);
    }

    public void testFailedAuthentication() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(null, new MockHttpSession());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        request.setAttribute("javax.servlet.request.X509Certificate",
                new X509Certificate[] {X509TestUtils.buildTestCertificate()});

        AuthenticationManager authMgr = new MockAuthenticationManager(false);

        ContextHolder.setContext(new SecureContextImpl());

        SecureContext ctx = SecureContextUtils.getSecureContext();

        ctx.setAuthentication(null);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);
        filter.afterPropertiesSet();
        filter.init(null);
        filter.doFilter(request, response, chain);
        filter.destroy();

        Authentication result = ctx.getAuthentication();

        assertNull(result);
    }

    public void testWithNoCertificate() throws Exception {
        MockHttpSession session = new MockHttpSession();
        MockHttpServletRequest request = new MockHttpServletRequest(null, session);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        AuthenticationManager authMgr = new MockX509AuthenticationManager();
        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);

        ContextHolder.setContext(new SecureContextImpl());
        filter.doFilter(request, response, chain);

        SecureContext ctx = SecureContextUtils.getSecureContext();

        assertNull("Authentication should be null", ctx.getAuthentication());
        assertTrue("BadCredentialsException should have been thrown",
                session.getAttribute(AbstractProcessingFilter.ACEGI_SECURITY_LAST_EXCEPTION_KEY) instanceof BadCredentialsException);
    }


    public void testWithExistingSecurityContext() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(null, new MockHttpSession());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain(true);

        Authentication token = new AnonymousAuthenticationToken("dummy", "dummy",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});

        ContextHolder.setContext(new SecureContextImpl());
        SecureContext ctx = SecureContextUtils.getSecureContext();

        ctx.setAuthentication(token);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.doFilter(request, response, chain);
        assertEquals("Existing token should be unchanged", token, ctx.getAuthentication());
    }

    //~ Inner Classes ==========================================================

    private static class MockX509AuthenticationManager implements AuthenticationManager {

        public Authentication authenticate(Authentication a) {
            if(!(a instanceof X509AuthenticationToken)) {
                TestCase.fail("Needed an X509Authentication token but found " + a);
            }

            if(a.getCredentials() == null) {
                throw new BadCredentialsException("Mock authentication manager rejecting null certificate");
            }

            return a;
        }
    }


}
