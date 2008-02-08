/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.providers.cas;

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.BadCredentialsException;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import org.springframework.security.providers.TestingAuthenticationToken;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.security.providers.cas.ticketvalidator.AbstractTicketValidator;

import org.springframework.security.ui.cas.CasProcessingFilter;

import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UserDetailsService;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.junit.Test;
import static org.junit.Assert.*;


/**
 * Tests {@link CasAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class CasAuthenticationProviderTests {
    //~ Methods ========================================================================================================

    private UserDetails makeUserDetails() {
        return new User("user", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
    }

    private UserDetails makeUserDetailsFromAuthoritiesPopulator() {
        return new User("user", "password", true, true, true, true,
            new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A"), new GrantedAuthorityImpl("ROLE_B")});
    }

    @Test
    public void statefulAuthenticationIsSuccessful() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
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
        assertEquals("https://localhost/portal/j_spring_cas_security_check", casResult.getProxyList().get(0));
        assertEquals("ST-123", casResult.getCredentials());
        assertEquals(new GrantedAuthorityImpl("ROLE_A"), casResult.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_B"), casResult.getAuthorities()[1]);
        assertEquals(cap.getKey().hashCode(), casResult.getKeyHash());

        // Now confirm the CasAuthenticationToken is automatically re-accepted.
        // To ensure TicketValidator not called again, set it to deliver an exception...
        cap.setTicketValidator(new MockTicketValidator(false));

        Authentication laterResult = cap.authenticate(result);
        assertEquals(result, laterResult);
    }

    @Test
    public void statelessAuthenticationIsSuccessful() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
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

    @Test(expected = BadCredentialsException.class)
    public void missingTicketIdIsDetected() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATEFUL_IDENTIFIER, "");

        Authentication result = cap.authenticate(token);
    }

    @Test(expected = BadCredentialsException.class)
    public void invalidKeyIsDetected() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        CasAuthenticationToken token = new CasAuthenticationToken("WRONG_KEY", makeUserDetails(), "credentials",
                new GrantedAuthority[] {new GrantedAuthorityImpl("XX")}, makeUserDetails(), new Vector(), "IOU-xxx");

        cap.authenticate(token);
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingAuthoritiesPopulator() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingKey() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingProxyDecider() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingStatelessTicketCache() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        // set this explicitly to null to test failure
        cap.setStatelessTicketCache(null);
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingTicketValidator() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider(true));
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.afterPropertiesSet();
    }

    @Test
    public void gettersAndSettersMatch() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        assertTrue(cap.getUserDetailsService() != null);
        assertTrue(cap.getCasProxyDecider() != null);
        assertEquals("qwerty", cap.getKey());
        assertTrue(cap.getStatelessTicketCache() != null);
        assertTrue(cap.getTicketValidator() != null);
    }

    @Test
    public void ignoresClassesItDoesNotSupport() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        TestingAuthenticationToken token = new TestingAuthenticationToken("user", "password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        assertFalse(cap.supports(TestingAuthenticationToken.class));

        // Try it anyway
        assertEquals(null, cap.authenticate(token));
    }

    @Test
    public void ignoresUsernamePasswordAuthenticationTokensWithoutCasIdentifiersAsPrincipal() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setCasProxyDecider(new MockProxyDecider());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("some_normal_user",
                "password", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_A")});
        assertEquals(null, cap.authenticate(token));
    }

    @Test
    public void supportsRequiredTokens() {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        assertTrue(cap.supports(UsernamePasswordAuthenticationToken.class));
        assertTrue(cap.supports(CasAuthenticationToken.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockAuthoritiesPopulator implements UserDetailsService {
        public UserDetails loadUserByUsername(String casUserId) throws AuthenticationException {
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
            throw new UnsupportedOperationException("mock method not implemented");
        }

        public void removeTicketFromCache(String serviceTicket) {
            throw new UnsupportedOperationException("mock method not implemented");
        }
    }

    private class MockTicketValidator extends AbstractTicketValidator {
        private boolean returnTicket;

        public MockTicketValidator(boolean returnTicket) {
            this.returnTicket = returnTicket;
        }

        public TicketResponse confirmTicketValid(String serviceTicket)
            throws AuthenticationException {
            if (returnTicket) {
                List list = new Vector();
                list.add("https://localhost/portal/j_spring_cas_security_check");

                return new TicketResponse("rod", list, "PGTIOU-0-R0zlgrl4pdAQwBvJWO3vnNpevwqStbSGcq3vKB2SqSFFRnjPHt");
            }

            throw new BadCredentialsException("As requested from mock");
        }
    }
}
