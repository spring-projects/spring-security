/* Copyright 2004, 2005 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.providers.x509;

import java.security.cert.X509Certificate;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;


/**
 * Tests {@link org.acegisecurity.providers.x509.X509AuthenticationProvider}
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

    public void testAuthenticationIsNullWithUnsupportedToken() {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();
        Authentication request = new UsernamePasswordAuthenticationToken("dummy",
                "dummy");
        Authentication result = provider.authenticate(request);
        assertNull(result);
    }

    public void testFailsWithNullCertificate() {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();

        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(false));

        try {
            provider.authenticate(new X509AuthenticationToken(null));
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException e) {
            //ignore
        }
    }

    public void testNormalOperation() throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();

        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(false));
        provider.afterPropertiesSet();

        Authentication result = provider.authenticate(X509TestUtils.createToken());

        assertNotNull(result);
        assertNotNull(result.getAuthorities());
    }

    public void testPopulatorRejectionCausesFailure() throws Exception {
        X509AuthenticationProvider provider = new X509AuthenticationProvider();
        provider.setX509AuthoritiesPopulator(new MockAuthoritiesPopulator(true));

        try {
            provider.authenticate(X509TestUtils.createToken());
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException e) {
            //ignore
        }
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

    //~ Inner Classes ==========================================================

    public static class MockAuthoritiesPopulator
        implements X509AuthoritiesPopulator {
        private boolean rejectCertificate;

        public MockAuthoritiesPopulator(boolean rejectCertificate) {
            this.rejectCertificate = rejectCertificate;
        }

        public UserDetails getUserDetails(X509Certificate userCertificate)
            throws AuthenticationException {
            if (rejectCertificate) {
                throw new BadCredentialsException("Invalid Certificate");
            }

            return new User("user", "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl(
                        "ROLE_B")});
        }
    }
}
