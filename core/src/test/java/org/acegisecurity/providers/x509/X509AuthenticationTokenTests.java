package net.sf.acegisecurity.providers.x509;

import junit.framework.TestCase;

import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.io.ByteArrayInputStream;

/**
 * @author Luke Taylor
 */
public class X509AuthenticationTokenTests extends TestCase {

    public X509AuthenticationTokenTests() {
    }

    public X509AuthenticationTokenTests(String s) {
        super(s);
    }

    public void setUp() throws Exception {
        super.setUp();
    }

    public void testAuthenticated() throws Exception {
        X509AuthenticationToken token = X509TestUtils.createToken();
        assertTrue(!token.isAuthenticated());
        token.setAuthenticated(true);
        assertTrue(token.isAuthenticated());
    }
}

