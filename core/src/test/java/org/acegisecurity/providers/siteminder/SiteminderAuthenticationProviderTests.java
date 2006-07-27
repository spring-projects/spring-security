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

package org.acegisecurity.providers.siteminder;

import java.util.HashMap;
import java.util.Map;

import junit.framework.TestCase;

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.LockedException;
import org.acegisecurity.providers.TestingAuthenticationToken;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.UserCache;
import org.acegisecurity.providers.dao.cache.EhCacheBasedUserCache;
import org.acegisecurity.providers.dao.cache.NullUserCache;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

/**
 * Tests {@link SiteminderAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id: SiteminderAuthenticationProviderTests.java 1582 2006-07-15 15:18:51Z smccrory $
 */
public class SiteminderAuthenticationProviderTests extends TestCase {
    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(SiteminderAuthenticationProviderTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testAuthenticateFailsIfAccountExpired() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserPeterAccountExpired());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown AccountExpiredException");
        } catch (AccountExpiredException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsIfAccountLocked() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserPeterAccountLocked());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown LockedException");
        } catch (LockedException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsIfCredentialsExpired() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserPeterCredentialsExpired());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown CredentialsExpiredException");
        } catch (CredentialsExpiredException expected) {
            assertTrue(true);
        }

    }

    public void testAuthenticateFailsIfUserDisabled() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserPeter());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown DisabledException");
        } catch (DisabledException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWhenUserDetailsServiceHasBackendFailure() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceSimulateBackendError());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown AuthenticationServiceException");
        } catch (AuthenticationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithEmptyUsername() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(null, "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithInvalidUsernameAndHideUserNotFoundExceptionFalse() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("INVALID_USER", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setHideUserNotFoundExceptions(false); // we want UsernameNotFoundExceptions
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithInvalidUsernameAndHideUserNotFoundExceptionsWithDefaultOfTrue() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("INVALID_USER", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        assertTrue(provider.isHideUserNotFoundExceptions());
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithMixedCaseUsernameIfDefaultChanged() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("MaRiSSA", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticates() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa", "koala");
        token.setDetails("192.168.0.1");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
        assertEquals(User.class, castResult.getPrincipal().getClass());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
        assertEquals("192.168.0.1", castResult.getDetails());
    }

    public void testAuthenticatesASecondTime() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        // Now try to authenticate with the previous result (with its UserDetails)
        Authentication result2 = provider.authenticate(result);

        if (!(result2 instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        assertEquals(result.getCredentials(), result2.getCredentials());
    }

    public void testAuthenticatesWithForcePrincipalAsString() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        provider.setUserCache(new MockUserCache());
        provider.setForcePrincipalAsString(true);

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
        assertEquals(String.class, castResult.getPrincipal().getClass());
        assertEquals("marissa", castResult.getPrincipal());
    }

    public void testDetectsNullBeingReturnedFromUserDetailsService() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa", "koala");

        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceReturnsNull());

        try {
            provider.authenticate(token);
            fail("Should have thrown AuthenticationServiceException");
        } catch (AuthenticationServiceException expected) {
            assertEquals("UserDetailsService returned null, which is an interface contract violation", expected
                    .getMessage());
        }
    }

    public void testGettersSetters() {
        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();

        provider.setUserCache(new EhCacheBasedUserCache());
        assertEquals(EhCacheBasedUserCache.class, provider.getUserCache().getClass());

        assertFalse(provider.isForcePrincipalAsString());
        provider.setForcePrincipalAsString(true);
        assertTrue(provider.isForcePrincipalAsString());
    }

    public void testStartupFailsIfNoUserDetailsService() throws Exception {
        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfNoUserCacheSet() throws Exception {
        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        provider.setUserDetailsService(new MockUserDetailsServiceUserMarissa());
        assertEquals(NullUserCache.class, provider.getUserCache().getClass());
        provider.setUserCache(null);

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccess() throws Exception {
        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        UserDetailsService userDetailsService = new MockUserDetailsServiceUserMarissa();
        provider.setUserDetailsService(userDetailsService);
        provider.setUserCache(new MockUserCache());
        assertEquals(userDetailsService, provider.getUserDetailsService());
        provider.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSupports() {
        SiteminderAuthenticationProvider provider = new SiteminderAuthenticationProvider();
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
        assertTrue(!provider.supports(TestingAuthenticationToken.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockUserDetailsServiceReturnsNull implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            return null;
        }
    }

    private class MockUserDetailsServiceSimulateBackendError implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            throw new DataRetrievalFailureException("This mock simulator is designed to fail");
        }
    }

    private class MockUserDetailsServiceUserMarissa implements UserDetailsService {
        private String password = "koala";

        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("marissa".equals(username)) {
                return new User("marissa", password, true, true, true, true, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    private class MockUserDetailsServiceUserMarissaWithSalt implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("marissa".equals(username)) {
                return new User("marissa", "koala{SYSTEM_SALT_VALUE}", true, true, true, true, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockUserDetailsServiceUserPeter implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("peter".equals(username)) {
                return new User("peter", "opal", false, true, true, true, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockUserDetailsServiceUserPeterAccountExpired implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, false, true, true, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockUserDetailsServiceUserPeterAccountLocked implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, true, true, false, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockUserDetailsServiceUserPeterCredentialsExpired implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, true, false, true, new GrantedAuthority[] {
                        new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO") });
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockUserCache implements UserCache {
        private Map cache = new HashMap();

        public UserDetails getUserFromCache(String username) {
            return (User) cache.get(username);
        }

        public void putUserInCache(UserDetails user) {
            cache.put(user.getUsername(), user);
        }

        public void removeUserFromCache(String username) {
        }
    }
}
