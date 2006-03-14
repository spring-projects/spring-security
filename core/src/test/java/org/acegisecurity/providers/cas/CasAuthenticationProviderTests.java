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

package org.acegisecurity.providers.cas;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import junit.framework.TestCase;

import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.TestingAuthenticationToken;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.cas.ticketvalidator.AbstractTicketValidator;
import org.acegisecurity.ui.cas.CasProcessingFilter;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;


/**
 * Tests {@link CasAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationProviderTests extends TestCase {
    //~ Constructors ===========================================================

    public CasAuthenticationProviderTests() {
        super();
    }

    public CasAuthenticationProviderTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(CasAuthenticationProviderTests.class);
    }

    public void testAuthenticateStateful() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATEFUL_IDENTIFIER,
                "ST-123");

        Authentication result = cap.authenticate(token);

        // Confirm ST-123 was NOT added to the cache
        assertTrue(cache.getByTicketId("ST-456") == null);

        if (!(result instanceof CasAuthenticationToken)) {
            fail("Should have returned a CasAuthenticationToken");
        }

        CasAuthenticationToken casResult = (CasAuthenticationToken) result;
        assertEquals(makeUserDetailsFromAuthoritiesPopulator(), casResult.getPrincipal());
        assertEquals("PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt",
            casResult.getProxyGrantingTicketIou());
        assertEquals("https://localhost/portal/j_acegi_cas_security_check",
            casResult.getProxyList().get(0));
        assertEquals("ST-123", casResult.getCredentials());
        assertEquals(new GrantedAuthorityImpl("ROLE_A"),
            casResult.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_B"),
            casResult.getAuthorities()[1]);
        assertEquals(cap.getKey().hashCode(), casResult.getKeyHash());

        // Now confirm the CasAuthenticationToken is automatically re-accepted.
        // To ensure TicketValidator not called again, set it to deliver an exception...
        cap.setTicketValidator(new MockTicketValidator(false));

        Authentication laterResult = cap.authenticate(result);
        assertEquals(result, laterResult);
    }

    public void testAuthenticateStateless() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATELESS_IDENTIFIER,
                "ST-456");

        Authentication result = cap.authenticate(token);

        // Confirm ST-456 was added to the cache
        assertTrue(cache.getByTicketId("ST-456") != null);

        if (!(result instanceof CasAuthenticationToken)) {
            fail("Should have returned a CasAuthenticationToken");
        }

        assertEquals(makeUserDetailsFromAuthoritiesPopulator(), result.getPrincipal());
        assertEquals("ST-456", result.getCredentials());

        // Now try to authenticate again. To ensure TicketValidator not
        // called again, set it to deliver an exception...
        cap.setTicketValidator(new MockTicketValidator(false));

        // Previously created UsernamePasswordAuthenticationToken is OK
        Authentication newResult = cap.authenticate(token);
        assertEquals(makeUserDetailsFromAuthoritiesPopulator(), newResult.getPrincipal());
        assertEquals("ST-456", newResult.getCredentials());
    }

    public void testDetectsAMissingTicketId() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATEFUL_IDENTIFIER,
                "");

        try {
            Authentication result = cap.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertEquals("Failed to provide a CAS service ticket to validate",
                expected.getMessage());
        }
    }

    public void testDetectsAnInvalidKey() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        CasAuthenticationToken token = new CasAuthenticationToken("WRONG_KEY",
               makeUserDetails(), "credentials",
                new GrantedAuthority[] {new GrantedAuthorityImpl("XX")},
                makeUserDetails(), new Vector(), "IOU-xxx");

        try {
            Authentication result = cap.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertEquals("The presented CasAuthenticationToken does not contain the expected key",
                expected.getMessage());
        }
    }

    public void testDetectsMissingAuthoritiesPopulator()
        throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));

        try {
            cap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A casAuthoritiesPopulator must be set",
                expected.getMessage());
        }
    }

    public void testDetectsMissingKey() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));

        try {
            cap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A Key is required so CasAuthenticationProvider can identify tokens it previously authenticated",
                expected.getMessage());
        }
    }

    public void testDetectsMissingProxyDecider() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));

        try {
            cap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A casProxyDecider must be set", expected.getMessage());
        }
    }

    public void testDetectsMissingStatelessTicketCache()
        throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setTicketValidator(new MockTicketValidator(true));

        try {
            cap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A statelessTicketCache must be set",
                expected.getMessage());
        }
    }

    public void testDetectsMissingTicketValidator() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());

        try {
            cap.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A ticketValidator must be set", expected.getMessage());
        }
    }

    public void testGettersSetters() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        assertTrue(cap.getCasAuthoritiesPopulator() != null);
        assertTrue(cap.getCasProxyDecider() != null);
        assertEquals("qwerty", cap.getKey());
        assertTrue(cap.getStatelessTicketCache() != null);
        assertTrue(cap.getTicketValidator() != null);
    }

    public void testIgnoresClassesItDoesNotSupport() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        TestingAuthenticationToken token = new TestingAuthenticationToken("user",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        assertFalse(cap.supports(TestingAuthenticationToken.class));

        // Try it anyway
        assertEquals(null, cap.authenticate(token));
    }

    public void testIgnoresUsernamePasswordAuthenticationTokensWithoutCasIdentifiersAsPrincipal()
        throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasAuthoritiesPopulator(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("some_normal_user",
                "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        assertEquals(null, cap.authenticate(token));
    }

    public void testSupports() {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        assertTrue(cap.supports(UsernamePasswordAuthenticationToken.class));
        assertTrue(cap.supports(CasAuthenticationToken.class));
    }

    private UserDetails makeUserDetails() {
        return new User("user", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                    "ROLE_TWO")});
    }
    
    private UserDetails makeUserDetailsFromAuthoritiesPopulator() {
    	return new User("user", "password", true, true, true, true,
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl(
                "ROLE_B")});
    }

    //~ Inner Classes ==========================================================

    private class MockAuthoritiesPopulator implements CasAuthoritiesPopulator {
        public UserDetails getUserDetails(String casUserId)
            throws AuthenticationException {
            return makeUserDetailsFromAuthoritiesPopulator();
        }
    }

    private class MockProxyDecider implements CasProxyDecider {
        private boolean acceptProxy;

        public MockProxyDecider(boolean acceptProxy) {
            this.acceptProxy = acceptProxy;
        }

        private MockProxyDecider() {
            super();
        }

        public void confirmProxyListTrusted(List proxyList)
            throws ProxyUntrustedException {
            if (acceptProxy) {
                return;
            } else {
                throw new ProxyUntrustedException("As requested from mock");
            }
        }
    }

    private class MockStatelessTicketCache implements StatelessTicketCache {
        private Map cache = new HashMap();

        public CasAuthenticationToken getByTicketId(String serviceTicket) {
            return (CasAuthenticationToken) cache.get(serviceTicket);
        }

        public void putTicketInCache(CasAuthenticationToken token) {
            cache.put(token.getCredentials().toString(), token);
        }

        public void removeTicketFromCache(CasAuthenticationToken token) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }

        public void removeTicketFromCache(String serviceTicket) {
            throw new UnsupportedOperationException(
                "mock method not implemented");
        }
    }

    private class MockTicketValidator extends AbstractTicketValidator {
        private boolean returnTicket;

        public MockTicketValidator(boolean returnTicket) {
            this.returnTicket = returnTicket;
        }

        private MockTicketValidator() {
            super();
        }

        public TicketResponse confirmTicketValid(String serviceTicket)
            throws AuthenticationException {
            if (returnTicket) {
                List list = new Vector();
                list.add("https://localhost/portal/j_acegi_cas_security_check");

                return new TicketResponse("marissa", list,
                    "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            }

            throw new BadCredentialsException("As requested from mock");
        }
    }
}
