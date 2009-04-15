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

package org.springframework.security.cas.authentication;


import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.StatelessTicketCache;
import org.springframework.security.cas.web.CasProcessingFilter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;



import java.util.HashMap;
import java.util.Map;

import org.jasig.cas.client.validation.Assertion;
import org.jasig.cas.client.validation.AssertionImpl;
import org.jasig.cas.client.validation.TicketValidationException;
import org.jasig.cas.client.validation.TicketValidator;
import org.junit.Test;
import static org.junit.Assert.*;


/**
 * Tests {@link CasAuthenticationProvider}.
 *
 * @author Ben Alex
 * @author Scott Battaglia
 * @version $Id$
 */
public class CasAuthenticationProviderTests {
    //~ Methods ========================================================================================================

    private UserDetails makeUserDetails() {
        return new User("user", "password", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
    }

    private UserDetails makeUserDetailsFromAuthoritiesPopulator() {
        return new User("user", "password", true, true, true, true,
                AuthorityUtils.createAuthorityList("ROLE_A", "ROLE_B"));
    }

    private ServiceProperties makeServiceProperties() {
        final ServiceProperties serviceProperties = new ServiceProperties();
        serviceProperties.setSendRenew(false);
        serviceProperties.setService("http://test.com");

        return serviceProperties;
    }

    @Test
    public void statefulAuthenticationIsSuccessful() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setServiceProperties(makeServiceProperties());

        cap.setTicketValidator(new MockTicketValidator(true));
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token =
            new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATEFUL_IDENTIFIER, "ST-123");
        token.setDetails("details");

        Authentication result = cap.authenticate(token);

        // Confirm ST-123 was NOT added to the cache
        assertTrue(cache.getByTicketId("ST-456") == null);

        if (!(result instanceof CasAuthenticationToken)) {
            fail("Should have returned a CasAuthenticationToken");
        }

        CasAuthenticationToken casResult = (CasAuthenticationToken) result;
        assertEquals(makeUserDetailsFromAuthoritiesPopulator(), casResult.getPrincipal());
        assertEquals("ST-123", casResult.getCredentials());
        assertEquals(new GrantedAuthorityImpl("ROLE_A"), casResult.getAuthorities().get(0));
        assertEquals(new GrantedAuthorityImpl("ROLE_B"), casResult.getAuthorities().get(1));
        assertEquals(cap.getKey().hashCode(), casResult.getKeyHash());
        assertEquals("details", casResult.getDetails());

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
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token =
            new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATELESS_IDENTIFIER, "ST-456");
        token.setDetails("details");

        Authentication result = cap.authenticate(token);

        // Confirm ST-456 was added to the cache
        assertTrue(cache.getByTicketId("ST-456") != null);

        if (!(result instanceof CasAuthenticationToken)) {
            fail("Should have returned a CasAuthenticationToken");
        }

        assertEquals(makeUserDetailsFromAuthoritiesPopulator(), result.getPrincipal());
        assertEquals("ST-456", result.getCredentials());
        assertEquals("details", result.getDetails());

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
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(CasProcessingFilter.CAS_STATEFUL_IDENTIFIER, "");

        cap.authenticate(token);
    }

    @Test(expected = BadCredentialsException.class)
    public void invalidKeyIsDetected() throws Exception {
        final Assertion assertion = new AssertionImpl("test");
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");

        StatelessTicketCache cache = new MockStatelessTicketCache();
        cap.setStatelessTicketCache(cache);
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();

        CasAuthenticationToken token = new CasAuthenticationToken("WRONG_KEY", makeUserDetails(), "credentials",
                AuthorityUtils.createAuthorityList("XX"), makeUserDetails(), assertion);

        cap.authenticate(token);
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingAuthoritiesPopulator() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingKey() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingStatelessTicketCache() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        // set this explicitly to null to test failure
        cap.setStatelessTicketCache(null);
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();
    }

    @Test(expected = IllegalArgumentException.class)
    public void detectsMissingTicketValidator() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();
    }

    @Test
    public void gettersAndSettersMatch() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();

        assertTrue(cap.getUserDetailsService() != null);
        assertEquals("qwerty", cap.getKey());
        assertTrue(cap.getStatelessTicketCache() != null);
        assertTrue(cap.getTicketValidator() != null);
    }

    @Test
    public void ignoresClassesItDoesNotSupport() throws Exception {
        CasAuthenticationProvider cap = new CasAuthenticationProvider();
        cap.setUserDetailsService(new MockAuthoritiesPopulator());
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
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
        cap.setKey("qwerty");
        cap.setStatelessTicketCache(new MockStatelessTicketCache());
        cap.setTicketValidator(new MockTicketValidator(true));
        cap.setServiceProperties(makeServiceProperties());
        cap.afterPropertiesSet();

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("some_normal_user",
                "password", AuthorityUtils.createAuthorityList("ROLE_A"));
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

    private class MockStatelessTicketCache implements StatelessTicketCache {
        private Map<String, CasAuthenticationToken> cache = new HashMap<String, CasAuthenticationToken>();

        public CasAuthenticationToken getByTicketId(String serviceTicket) {
            return cache.get(serviceTicket);
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

    private class MockTicketValidator implements TicketValidator {
        private boolean returnTicket;

        public MockTicketValidator(boolean returnTicket) {
            this.returnTicket = returnTicket;
        }

        public Assertion validate(final String ticket, final String service)
                throws TicketValidationException {
            if (returnTicket) {
                return new AssertionImpl("rod");
            }
            throw new BadCredentialsException("As requested from mock");
        }
    }
}
