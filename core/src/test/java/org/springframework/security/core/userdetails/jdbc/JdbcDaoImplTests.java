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

package org.springframework.security.core.userdetails.jdbc;

import junit.framework.TestCase;

import org.springframework.security.PopulatedDatabase;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;


/**
 * Tests {@link JdbcDaoImpl}.
 *
 * @author Ben Alex
 */
public class JdbcDaoImplTests extends TestCase {

    //~ Methods ========================================================================================================

    private JdbcDaoImpl makePopulatedJdbcDao() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        dao.setDataSource(PopulatedDatabase.getDataSource());
        dao.afterPropertiesSet();

        return dao;
    }

    private JdbcDaoImpl makePopulatedJdbcDaoWithRolePrefix() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        dao.setDataSource(PopulatedDatabase.getDataSource());
        dao.setRolePrefix("ARBITRARY_PREFIX_");
        dao.afterPropertiesSet();

        return dao;
    }

    public void testCheckDaoAccessUserSuccess() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        UserDetails user = dao.loadUserByUsername("rod");
        assertEquals("rod", user.getUsername());
        assertEquals("koala", user.getPassword());
        assertTrue(user.isEnabled());

        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_TELLER"));
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_SUPERVISOR"));
    }

    public void testCheckDaoOnlyReturnsGrantedAuthoritiesGrantedToUser() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        UserDetails user = dao.loadUserByUsername("scott");
        assertEquals(1, user.getAuthorities().size());
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ROLE_TELLER"));
    }

    public void testCheckDaoReturnsCorrectDisabledProperty() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        UserDetails user = dao.loadUserByUsername("peter");
        assertTrue(!user.isEnabled());
    }

    public void testGettersSetters() {
        JdbcDaoImpl dao = new JdbcDaoImpl();
        dao.setAuthoritiesByUsernameQuery("SELECT * FROM FOO");
        assertEquals("SELECT * FROM FOO", dao.getAuthoritiesByUsernameQuery());

        dao.setUsersByUsernameQuery("SELECT USERS FROM FOO");
        assertEquals("SELECT USERS FROM FOO", dao.getUsersByUsernameQuery());
    }

    public void testLookupFailsIfUserHasNoGrantedAuthorities() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();

        try {
            dao.loadUserByUsername("cooper");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertEquals("User cooper has no GrantedAuthority", expected.getMessage());
        }
    }

    public void testLookupFailsWithWrongUsername() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();

        try {
            dao.loadUserByUsername("UNKNOWN_USER");
            fail("Should have thrown UsernameNotFoundException");
        } catch (UsernameNotFoundException expected) {
            assertTrue(true);
        }
    }

    public void testLookupSuccessWithMixedCase() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        assertEquals("koala", dao.loadUserByUsername("rod").getPassword());
        assertEquals("wombat", dao.loadUserByUsername("ScOTt").getPassword());
    }

    public void testRolePrefixWorks() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDaoWithRolePrefix();
        assertEquals("ARBITRARY_PREFIX_", dao.getRolePrefix());

        UserDetails user = dao.loadUserByUsername("rod");
        assertEquals("rod", user.getUsername());
        assertEquals(2, user.getAuthorities().size());

        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ARBITRARY_PREFIX_ROLE_TELLER"));
        assertTrue(AuthorityUtils.authorityListToSet(user.getAuthorities()).contains("ARBITRARY_PREFIX_ROLE_SUPERVISOR"));
    }

    public void testGroupAuthoritiesAreLoadedCorrectly() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        dao.setEnableAuthorities(false);
        dao.setEnableGroups(true);

        UserDetails jerry = dao.loadUserByUsername("jerry");
        assertEquals(3, jerry.getAuthorities().size());
    }

    public void testDuplicateGroupAuthoritiesAreRemoved() throws Exception {
        JdbcDaoImpl dao = makePopulatedJdbcDao();
        dao.setEnableAuthorities(false);
        dao.setEnableGroups(true);
        // Tom has roles A, B, C and B, C duplicates
        UserDetails tom = dao.loadUserByUsername("tom");
        assertEquals(3, tom.getAuthorities().size());
    }

    public void testStartupFailsIfDataSourceNotSet() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();

        try {
            dao.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }

    public void testStartupFailsIfUserMapSetToNull() throws Exception {
        JdbcDaoImpl dao = new JdbcDaoImpl();

        try {
            dao.setDataSource(null);
            dao.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            assertTrue(true);
        }
    }
}
