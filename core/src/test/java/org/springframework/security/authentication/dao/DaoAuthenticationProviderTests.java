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

package org.springframework.security.authentication.dao;

import java.util.List;

import junit.framework.TestCase;

import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.EhCacheBasedUserCache;
import org.springframework.security.core.userdetails.cache.NullUserCache;


/**
 * Tests {@link DaoAuthenticationProvider}.
 *
 * @author Ben Alex
 */
public class DaoAuthenticationProviderTests extends TestCase {
    private static final List<GrantedAuthority> ROLES_12 = AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO");


    //~ Methods ========================================================================================================

    public void testAuthenticateFailsForIncorrectPasswordCase() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "KOala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testReceivedBadCredentialsWhenCredentialsNotProvided() {
        // Test related to SEC-434
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("rod", null);
        try {
            provider.authenticate(authenticationToken);
            fail("Expected BadCredenialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsIfAccountExpired() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserPeterAccountExpired());
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

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserPeterAccountLocked());
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

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserPeterCredentialsExpired());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown CredentialsExpiredException");
        } catch (CredentialsExpiredException expected) {
            assertTrue(true);
        }

        // Check that wrong password causes BadCredentialsException, rather than CredentialsExpiredException
        token = new UsernamePasswordAuthenticationToken("peter", "wrong_password");

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsIfUserDisabled() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter", "opal");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserPeter());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown DisabledException");
        } catch (DisabledException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWhenAuthenticationDaoHasBackendFailure() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoSimulateBackendError());
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

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithInvalidPassword() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod",
                "INVALID_PASSWORD");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
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

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setHideUserNotFoundExceptions(false); // we want UsernameNotFoundExceptions
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
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

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        assertTrue(provider.isHideUserNotFoundExceptions());
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithMixedCaseUsernameIfDefaultChanged() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("RoD", "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticates() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");
        token.setDetails("192.168.0.1");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
        assertEquals(User.class, castResult.getPrincipal().getClass());
        assertEquals("koala", castResult.getCredentials());
        assertTrue(AuthorityUtils.authorityListToSet(castResult.getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(castResult.getAuthorities()).contains("ROLE_TWO"));
        assertEquals("192.168.0.1", castResult.getDetails());
    }

    public void testAuthenticatesASecondTime() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
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

    public void testAuthenticatesWhenASaltIsUsed() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        SystemWideSaltSource salt = new SystemWideSaltSource();
        salt.setSystemWideSalt("SYSTEM_SALT_VALUE");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrodWithSalt());
        provider.setSaltSource(salt);
        provider.setUserCache(new MockUserCache());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        assertEquals(User.class, result.getPrincipal().getClass());

        // We expect original credentials user submitted to be returned
        assertEquals("koala", result.getCredentials());
        assertTrue(AuthorityUtils.authorityListToSet(result.getAuthorities()).contains("ROLE_ONE"));
        assertTrue(AuthorityUtils.authorityListToSet(result.getAuthorities()).contains("ROLE_TWO"));
    }

    public void testAuthenticatesWithForcePrincipalAsString() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
        provider.setUserCache(new MockUserCache());
        provider.setForcePrincipalAsString(true);

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail("Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
        assertEquals(String.class, castResult.getPrincipal().getClass());
        assertEquals("rod", castResult.getPrincipal());
    }

    public void testDetectsNullBeingReturnedFromAuthenticationDao() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoReturnsNull());

        try {
            provider.authenticate(token);
            fail("Should have thrown AuthenticationServiceException");
        } catch (AuthenticationServiceException expected) {
            assertEquals("UserDetailsService returned null, which is an interface contract violation",
                expected.getMessage());
        }
    }

    public void testGettersSetters() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new ShaPasswordEncoder());
        assertEquals(ShaPasswordEncoder.class, provider.getPasswordEncoder().getClass());

        provider.setSaltSource(new SystemWideSaltSource());
        assertEquals(SystemWideSaltSource.class, provider.getSaltSource().getClass());

        provider.setUserCache(new EhCacheBasedUserCache());
        assertEquals(EhCacheBasedUserCache.class, provider.getUserCache().getClass());

        assertFalse(provider.isForcePrincipalAsString());
        provider.setForcePrincipalAsString(true);
        assertTrue(provider.isForcePrincipalAsString());
    }

    public void testGoesBackToAuthenticationDaoToObtainLatestPasswordIfCachedPasswordSeemsIncorrect() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("rod", "koala");

        MockAuthenticationDaoUserrod authenticationDao = new MockAuthenticationDaoUserrod();
        MockUserCache cache = new MockUserCache();
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(authenticationDao);
        provider.setUserCache(cache);

        // This will work, as password still "koala"
        provider.authenticate(token);

        // Check "rod = koala" ended up in the cache
        assertEquals("koala", cache.getUserFromCache("rod").getPassword());

        // Now change the password the AuthenticationDao will return
        authenticationDao.setPassword("easternLongNeckTurtle");

        // Now try authentication again, with the new password
        token = new UsernamePasswordAuthenticationToken("rod", "easternLongNeckTurtle");
        provider.authenticate(token);

        // To get this far, the new password was accepted
        // Check the cache was updated
        assertEquals("easternLongNeckTurtle", cache.getUserFromCache("rod").getPassword());
    }

    public void testStartupFailsIfNoAuthenticationDao()
        throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfNoUserCacheSet() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(new MockAuthenticationDaoUserrod());
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
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        UserDetailsService userDetailsService = new MockAuthenticationDaoUserrod();
        provider.setUserDetailsService(userDetailsService);
        provider.setUserCache(new MockUserCache());
        assertEquals(userDetailsService, provider.getUserDetailsService());
        provider.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSupports() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
        assertTrue(!provider.supports(TestingAuthenticationToken.class));
    }

    //~ Inner Classes ==================================================================================================

    private class MockAuthenticationDaoReturnsNull implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            return null;
        }
    }

    private class MockAuthenticationDaoSimulateBackendError implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            throw new DataRetrievalFailureException("This mock simulator is designed to fail");
        }
    }

    private class MockAuthenticationDaoUserrod implements UserDetailsService {
        private String password = "koala";

        public UserDetails loadUserByUsername(String username) {
            if ("rod".equals(username)) {
                return new User("rod", password, true, true, true, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }

        public void setPassword(String password) {
            this.password = password;
        }
    }

    private class MockAuthenticationDaoUserrodWithSalt implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            if ("rod".equals(username)) {
                return new User("rod", "koala{SYSTEM_SALT_VALUE}", true, true, true, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockAuthenticationDaoUserPeter implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            if ("peter".equals(username)) {
                return new User("peter", "opal", false, true, true, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockAuthenticationDaoUserPeterAccountExpired implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, false, true, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockAuthenticationDaoUserPeterAccountLocked implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, true, true, false, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }

    private class MockAuthenticationDaoUserPeterCredentialsExpired implements UserDetailsService {
        public UserDetails loadUserByUsername(String username) {
            if ("peter".equals(username)) {
                return new User("peter", "opal", true, true, false, true, ROLES_12);
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }
}
