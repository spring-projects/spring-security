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

package net.sf.acegisecurity.providers.dao.ldap;

import junit.framework.TestCase;

import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.UserDetails;

import org.springframework.dao.DataAccessException;


/**
 * DOCUMENT ME!
 *
 * @author Karel Miarka
 */
public class TestLdapPasswordAuthenticationDao extends TestCase {
    //~ Static fields/initializers =============================================

    static String HOSTNAME = "ntserver";
    static String HOST_IP = "192.168.1.1";
    static String ROOT_CONTEXT = "DC=issa,DC=cz";
    static String USER_CONTEXT = "CN=Users";

    // objectClass is a mandatory attribute in AD with list of classes
    // so it is suitable for testing
    static String ROLES_ATTRIBUTE = "objectClass";
    static String USERNAME = "Karel Miarka";
    static String PASSWORD = "password";

    //~ Instance fields ========================================================

    LdapPasswordAuthenticationDao dao;

    //~ Methods ================================================================

    public void testAuthenticationEmptyPassword() {
        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME, "");
            fail();
        } catch (BadCredentialsException ex) {
            assertEquals("Empty password", ex.getMessage());
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidHost() {
        dao.setHost("xxx");

        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME,
                    PASSWORD);
            fail();
        } catch (DataAccessException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidPassword() {
        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME, "xxx");
            fail();
        } catch (BadCredentialsException ex) {
            assertTrue(ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidPort() {
        dao.setPort(123);

        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME,
                    PASSWORD);
            fail();
        } catch (DataAccessException ex) {
            assertTrue(true);
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidRolesAttribute() {
//		dao.setRolesAttribute("xxx");
        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME,
                    PASSWORD);
            fail();
        } catch (BadCredentialsException ex) {
            assertEquals("The user has no granted authorities or the rolesAttribute is invalid",
                ex.getMessage());
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidRootContext() {
        dao.setRootContext("DN=xxx");

        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME,
                    PASSWORD);
            fail();
        } catch (BadCredentialsException ex) {
            assertTrue(ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidUserContext() {
        dao.setUserContext("CN=xxx");

        try {
            UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME,
                    PASSWORD);
            fail();
        } catch (BadCredentialsException ex) {
            assertTrue(ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationInvalidUsername() {
        try {
            UserDetails user = dao.loadUserByUsernameAndPassword("xxx", PASSWORD);
            fail();
        } catch (BadCredentialsException ex) {
            assertTrue(ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        } catch (Exception ex) {
            fail();
        }
    }

    public void testAuthenticationValid() {
        UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME, PASSWORD);
        assertEquals(USERNAME, user.getUsername());
        assertEquals(PASSWORD, user.getPassword());
        assertEquals(new GrantedAuthorityImpl("ROLE_TOP"),
            user.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_USER"),
            user.getAuthorities()[3]);
    }

    public void testAuthenticationValidWithIpHost() {
        dao.setHost(HOST_IP);

        UserDetails user = dao.loadUserByUsernameAndPassword(USERNAME, PASSWORD);
        assertEquals(USERNAME, user.getUsername());
        assertEquals(PASSWORD, user.getPassword());
        assertEquals(new GrantedAuthorityImpl("ROLE_TOP"),
            user.getAuthorities()[0]);
        assertEquals(new GrantedAuthorityImpl("ROLE_USER"),
            user.getAuthorities()[3]);
    }

    protected void setUp() throws Exception {
        super.setUp();
        dao = new LdapPasswordAuthenticationDao();
        dao.setHost(HOSTNAME); // ldap://lojza:389/DC=elcom,DC=cz
        dao.setPort(389);
        dao.setRootContext(ROOT_CONTEXT);
        dao.setUserContext(USER_CONTEXT);

        //	dao.setRolesAttribute(ROLES_ATTRIBUTE);
    }
}
