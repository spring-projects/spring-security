package net.sf.acegisecurity.providers.x509;

import junit.framework.TestCase;
import net.sf.acegisecurity.*;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;

import java.security.cert.X509Certificate;

/**
 * Tests {@link net.sf.acegisecurity.providers.x509.X509AuthenticationProvider}
 *
 * @author Luke Taylor
 * @version $Id$
 */
public class X509AuthenticationProviderTests extends TestCase {
    //~ Constructors ===========================================================

    public X509AuthenticationProviderTests() {
        super();
    }

    public X509AuthenticationProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testRequiresPopulator() throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();
        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException failed) {
            //ignored
        }
    }

    public void testNormalOperation () throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();

        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(false));
        provider.afterPropertiesSet();

        Authentication result = provider.authenticate(X509TestUtils.createToken());

        assertNotNull(result);
        assertNotNull(result.getAuthorities());
    }

    public void testFailsWithNullCertificate() {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();

        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(false));
        try {
            provider.authenticate(new X509AuthenticationToken(null));
            fail("Should have thrown BadCredentialsException");
        } catch(BadCredentialsException e) {
            //ignore
        }
    }

    public void testPopulatorRejectionCausesFailure() throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();
        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(true));
        try {
            provider.authenticate(X509TestUtils.createToken());
            fail("Should have thrown BadCredentialsException");
        } catch(BadCredentialsException e) {
            //ignore
        }
    }

    public void testAuthenticationIsNullWithUnsupportedToken() {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();
        Authentication request = new UsernamePasswordAuthenticationToken("dummy","dummy");
        Authentication result = provider.authenticate(request);
        assertNull(result);
    }

    //~ Inner Classes ==========================================================

    public static class MockAuthoritiesPopulator implements X509AuthoritiesPopulator {
        private boolean rejectCertificate;

        public MockAuthoritiesPopulator(boolean rejectCertificate) {
            this.rejectCertificate = rejectCertificate;
        }

        public UserDetails getUserDetails(X509Certificate userCertificate) throws AuthenticationException {
            if(rejectCertificate) {
                throw new BadCredentialsException("Invalid Certificate");
            }

            return new User ("user", "password", true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl(
                        "ROLE_B")});
        }
    }



}
