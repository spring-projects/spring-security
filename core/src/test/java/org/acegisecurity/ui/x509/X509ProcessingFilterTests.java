package net.sf.acegisecurity.ui.x509;

import junit.framework.TestCase;

//import org.mortbay.http.*;
//import org.mortbay.jetty.servlet.*;

import java.net.URL;
import java.io.IOException;
import java.security.cert.X509Certificate;

import net.sf.acegisecurity.*;
import net.sf.acegisecurity.context.security.SecureContext;
import net.sf.acegisecurity.context.security.SecureContextUtils;
import net.sf.acegisecurity.context.security.SecureContextImpl;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.providers.x509.X509TestUtils;
import net.sf.acegisecurity.ui.cas.CasProcessingFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.ServletException;

/**
 * @author Luke
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

    public void testNormalOperation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(null, new MockHttpSession());
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();

        request.setAttribute("javax.servlet.request.X509Certificate",
                new X509Certificate[] {X509TestUtils.buildTestCertificate()});

        MockAuthenticationManager authMgr = new MockAuthenticationManager(true);

        ContextHolder.setContext(new SecureContextImpl());

        SecureContext ctx = SecureContextUtils.getSecureContext();

        ctx.setAuthentication(null);

        X509ProcessingFilter filter = new X509ProcessingFilter();

        filter.setAuthenticationManager(authMgr);
        filter.afterPropertiesSet();
        filter.init(null);
        filter.doFilter(request, response, chain);

        Authentication result = ctx.getAuthentication();

        assertNotNull(result);
    }

    //~ Inner Classes ==========================================================

    private class MockFilterChain implements FilterChain {
        public void doFilter(ServletRequest arg0, ServletResponse arg1)
            throws IOException, ServletException {
                // do nothing.
        }
    }
//    public void testFilterIntegration() throws Exception {
//
//        // set up server.
//        HttpServer server = new HttpServer();
//        try {
//            SunJsseListener listener = new SunJsseListener();
//            listener.setNeedClientAuth(true);
//            listener.setPort(9443);
////            listener.setKeystore();
//
//            server.addListener(listener);
//
//            // map servlet.
//            HttpContext context = server.getContext("/");
//
////            ServletHandler handler = new ServletHandler();
////            handler.addServlet("MyServlet", "/myServlet", MyServlet.class.getName());
////            context.addHandler(handler);
//
//            // start server.
//            server.start();
//
//            // test client code against url.
//            URL url = new URL("http://localhost:" + 9443 + "/myServlet");
//
//
//
//        }
//        finally {
//          server.stop();
//        }
//    }



}
