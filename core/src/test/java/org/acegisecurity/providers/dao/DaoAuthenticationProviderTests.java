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

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;


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
        provider.setAuthenticationDao(new MockAuthenticationDaoUserMarissa());

        Authentication result = provider.authenticate(token);

        if (!(result instanceof UsernamePasswordAuthenticationToken)) {
            fail(
                "Should have returned instance of UsernamePasswordAuthenticationToken");
        }

        UsernamePasswordAuthenticationToken castResult = (UsernamePasswordAuthenticationToken) result;
        assertEquals("marissa", castResult.getPrincipal());
        assertEquals("koala", castResult.getCredentials());
        assertEquals("ROLE_ONE", castResult.getAuthorities()[0].getAuthority());
        assertEquals("ROLE_TWO", castResult.getAuthorities()[1].getAuthority());
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

    public void testStartupSuccess() throws Exception {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        AuthenticationDao dao = new MockAuthenticationDaoUserMarissa();
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
