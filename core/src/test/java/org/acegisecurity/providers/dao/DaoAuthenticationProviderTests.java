/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.providers.dao;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.AuthenticationServiceException;
import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.DisabledException;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;
import net.sf.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import net.sf.acegisecurity.providers.dao.salt.SystemWideSaltSource;
import net.sf.acegisecurity.providers.encoding.ShaPasswordEncoder;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;

import java.util.Date;


/**
 * Tests {@link DaoAuthenticationProvider}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoAuthenticationProviderTests extends TestCase {
    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public static void main(String[] args) {
        junit.textui.TestRunner.run(DaoAuthenticationProviderTests.class);
    }

    public void testAuthenticateFailsForIncorrectPasswordCase() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "KOala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsIfUserDisabled() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("peter",
                "opal");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserPeter());

        try {
            provider.authenticate(token);
            fail("Should have thrown DisabledException");
        } catch (DisabledException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWhenAuthenticationDaoHasBackendFailure() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoSimulateBackendError());

        try {
            provider.authenticate(token);
            fail("Should have thrown AuthenticationServiceException");
        } catch (AuthenticationServiceException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithInvalidPassword() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "INVALID_PASSWORD");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithInvalidUsername() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("INVALID_USER",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticateFailsWithMixedCaseUsernameIfDefaultChanged() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("MaRiSSA",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testAuthenticates() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof DaoAuthenticationToken)) {
            fail("Should have returned instance of DaoAuthenticationToken");
        }

        DaoAuthenticationToken castResult = (DaoAuthenticationToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
        assertEquals(provider.getKey().hashCode(), castResult.getKeyHash());
    }

    public void testAuthenticatesThenAcceptsCreatedTokenAutomatically() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof DaoAuthenticationToken)) {
            fail("Should have returned instance of DaoAuthenticationToken");
        }

        DaoAuthenticationToken castResult = (DaoAuthenticationToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals(provider.getKey().hashCode(), castResult.getKeyHash());
        assertTrue(castResult.getExpires().after(new Date()));

        // Now try to re-authenticate
        // Set provider to null, so we get a NullPointerException if it tries to re-authenticate
        provider.setAuthenticationDao(null);

        Authentication secondResult = provider.authenticate(result);

        if (!(secondResult instanceof DaoAuthenticationToken)) {
            fail("Should have returned instance of DaoAuthenticationToken");
        }

        // Should still have the same expiry time as original
        assertEquals(castResult.getExpires(),
            ((DaoAuthenticationToken) secondResult).getExpires());
    }

    public void testAuthenticatesWhenASaltIsUsed() {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "koala");

        SystemWideSaltSource salt = new SystemWideSaltSource();
        salt.setSystemWideSalt("SYSTEM_SALT_VALUE");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissaWithSalt());
        provider.setSaltSource(salt);

        Authentication result = provider.authenticate(token);

        if (!(result instanceof DaoAuthenticationToken)) {
            fail(
                "Should have returned instance of DaoPasswordAuthenticationToken");
        }

        DaoAuthenticationToken castResult = (DaoAuthenticationToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala{SYSTEM_SALT_VALUE}", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
        assertEquals(provider.getKey().hashCode(), castResult.getKeyHash());
    }

    public void testDaoAuthenticationTokensThatHaveExpiredAreRefreshed()
        throws Exception {
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("marissa",
                "koala");

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setRefreshTokenInterval(0); // never cache
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof DaoAuthenticationToken)) {
            fail("Should have returned instance of DaoAuthenticationToken");
        }

        DaoAuthenticationToken castResult = (DaoAuthenticationToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals(provider.getKey().hashCode(), castResult.getKeyHash());
        Thread.sleep(1000);
        assertTrue(castResult.getExpires().before(new Date())); // already expired

        // Now try to re-authenticate
        Authentication secondResult = provider.authenticate(result);

        if (!(secondResult instanceof DaoAuthenticationToken)) {
            fail("Should have returned instance of DaoAuthenticationToken");
        }

        // Should still have a later expiry time than original
        assertTrue(castResult.getExpires().before(((DaoAuthenticationToken) secondResult)
                .getExpires()));
    }

    public void testDaoAuthenticationTokensWithWrongKeyAreRejected()
        throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("x");
        provider.setRefreshTokenInterval(0); // never cache
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        DaoAuthenticationToken token = new DaoAuthenticationToken("key",
                new Date(), "Test", "Password",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                        "ROLE_TWO")});

        try {
            provider.authenticate(token);
            fail("Should have thrown BadCredentialsException");
        } catch (BadCredentialsException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new ShaPasswordEncoder());
        assertEquals(ShaPasswordEncoder.class,
            provider.getPasswordEncoder().getClass());

        provider.setSaltSource(new SystemWideSaltSource());
        assertEquals(SystemWideSaltSource.class,
            provider.getSaltSource().getClass());
    }

    public void testStartupFailsIfNoAuthenticationDao()
        throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setKey("xxx");

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfNoKeySet() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        try {
            provider.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupSuccess() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        AuthenticationDao dao = new MockAuthenticationDaoUserMarissa();
        provider.setKey("x");
        provider.setAuthenticationDao(dao);
        assertEquals(dao, provider.getAuthenticationDao());
        provider.afterPropertiesSet();
        assertTrue(true);
    }

    public void testSupports() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        assertTrue(provider.supports(UsernamePasswordAuthenticationToken.class));
        assertTrue(!provider.supports(TestingAuthenticationToken.class));
    }

    //~ Inner Classes ==========================================================

    private class MockAuthenticationDaoSimulateBackendError
        implements AuthenticationDao {
        public User loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            throw new DataRetrievalFailureException(
                "This mock simulator is designed to fail");
        }
    }

    private class MockAuthenticationDaoUserMarissa implements AuthenticationDao {
        public User loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if ("marissa".equals(username)) {
                return new User("marissa", "koala", true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: "
                    + username);
            }
        }
    }

    private class MockAuthenticationDaoUserMarissaWithSalt
        implements AuthenticationDao {
        public User loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if ("marissa".equals(username)) {
                return new User("marissa", "koala{SYSTEM_SALT_VALUE}", true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: "
                    + username);
            }
        }
    }

    private class MockAuthenticationDaoUserPeter implements AuthenticationDao {
        public User loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if ("peter".equals(username)) {
                return new User("peter", "opal", false,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl(
                            "ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: "
                    + username);
            }
        }
    }
}
