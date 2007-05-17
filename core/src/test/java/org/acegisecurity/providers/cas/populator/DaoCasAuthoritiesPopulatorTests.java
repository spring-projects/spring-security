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

package org.acegisecurity.providers.cas.populator;

import junit.framework.TestCase;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataRetrievalFailureException;


/**
 * Tests {@link DaoCasAuthoritiesPopulator}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class DaoCasAuthoritiesPopulatorTests extends TestCase {
    //~ Constructors ===================================================================================================

    public DaoCasAuthoritiesPopulatorTests() {
        super();
    }

    public DaoCasAuthoritiesPopulatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ========================================================================================================

    public static void main(String[] args) {
        junit.textui.TestRunner.run(DaoCasAuthoritiesPopulatorTests.class);
    }

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testDetectsMissingAuthenticationDao() throws Exception {
        DaoCasAuthoritiesPopulator populator = new DaoCasAuthoritiesPopulator();

        try {
            populator.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertEquals("A UserDetailsService must be set", expected.getMessage());
        }
    }

    public void testGetGrantedAuthoritiesForInvalidUsername()
        throws Exception {
        DaoCasAuthoritiesPopulator populator = new DaoCasAuthoritiesPopulator();
        populator.setUserDetailsService(new MockAuthenticationDaoUserMarissa());
        populator.afterPropertiesSet();

        try {
            populator.getUserDetails("scott");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testGetGrantedAuthoritiesForValidUsername()
        throws Exception {
        DaoCasAuthoritiesPopulator populator = new DaoCasAuthoritiesPopulator();
        populator.setUserDetailsService(new MockAuthenticationDaoUserMarissa());
        populator.afterPropertiesSet();

        UserDetails results = populator.getUserDetails("marissa");
        assertEquals(2, results.getAuthorities().length);
        assertEquals(new GrantedAuthorityImpl("ROLE_ONE"), results.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_TWO"), results.getAuthorities()[1]);
    }

    public void testGetGrantedAuthoritiesWhenDaoThrowsException()
        throws Exception {
        DaoCasAuthoritiesPopulator populator = new DaoCasAuthoritiesPopulator();
        populator.setUserDetailsService(new MockAuthenticationDaoSimulateBackendError());
        populator.afterPropertiesSet();

        try {
            populator.getUserDetails("THE_DAO_WILL_FAIL");
            fail("Should have thrown DataRetrievalFailureException");
        } catch (DataRetrievalFailureException expected) {
            assertTrue(true);
        }
    }

    public void testGettersSetters() {
        DaoCasAuthoritiesPopulator populator = new DaoCasAuthoritiesPopulator();
        UserDetailsService dao = new MockAuthenticationDaoUserMarissa();
        populator.setUserDetailsService(dao);
        assertEquals(dao, populator.getUserDetailsService());
    }

    //~ Inner Classes ==================================================================================================

    private class MockAuthenticationDaoSimulateBackendError implements UserDetailsService {
        public long getRefreshDuration() {
            return 0;
        }

        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            throw new DataRetrievalFailureException("This mock simulator is designed to fail");
        }
    }

    private class MockAuthenticationDaoUserMarissa implements UserDetailsService {
        public long getRefreshDuration() {
            return 0;
        }

        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if ("marissa".equals(username)) {
                return new User("marissa", "koala", true, true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE"), new GrantedAuthorityImpl("ROLE_TWO")});
            } else {
                throw new UsernameNotFoundException("Could not find: " + username);
            }
        }
    }
}
