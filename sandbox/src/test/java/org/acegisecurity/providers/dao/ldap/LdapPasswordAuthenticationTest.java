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

package net.sf.acegisecurity.providers.dao.ldap;

import net.sf.acegisecurity.BadCredentialsException;
import net.sf.acegisecurity.UserDetails;

import javax.naming.NamingException;


/**
 * DOCUMENT ME!
 *
 * @author $author$
 * @version $Revision$
 */
public class LdapPasswordAuthenticationTest extends BaseLdapTestCase {
    //~ Instance fields ========================================================

    private LdapPasswordAuthenticationDao dao;
    private String DEFAULT_ROLE = "DEFAULT_ROLE";

    //~ Methods ================================================================

    public void testEmptyRoles() {
        dao.setUserContext("uid={0},ou=users,ou=system");

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("user.two",
                    "plaintext2");
            fail("No roles are accessible for user; this test _should_ fail.");
        } catch (BadCredentialsException ex) {
            assertTrue("No roles are accessible for user; this test _should_ fail.",
                ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        }
    }

    public void testSimpleCnUser() throws NamingException {
        dao.setUserContext("cn={0},ou=users,ou=system");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("user.two",
                    "plaintext2");
            assertEquals(1, userDetails.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails.getAuthorities()[0].getAuthority());
        } catch (BadCredentialsException ex) {
            fail();
        }
    }

    public void testSimpleMultiUserContext() throws NamingException {
        dao.setUserContexts(new String[] {"uid={0},ou=users,ou=system", "cn={0},ou=users,ou=system"});
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("one.user",
                    "plaintext");
            assertEquals(1, userDetails.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails.getAuthorities()[0].getAuthority());

            UserDetails userDetails2 = dao.loadUserByUsernameAndPassword("user.two",
                    "plaintext2");
            assertEquals(1, userDetails2.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails2.getAuthorities()[0].getAuthority());
        } catch (BadCredentialsException ex) {
            fail();
        }
    }

    public void testSimpleUidUser() throws NamingException {
        dao.setUserContext("uid={0},ou=users,ou=system");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("one.user",
                    "plaintext");
            assertEquals(1, userDetails.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails.getAuthorities()[0].getAuthority());
        } catch (BadCredentialsException ex) {
            fail();
        }
    }

    public void testSimpleUidUserBadPassword() throws NamingException {
        dao.setUserContext("uid={0},ou=users,ou=system");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("one.user",
                    "plainlywrong");

            //assertEquals(1, userDetails.getAuthorities().length );
            //assertEquals(DEFAULT_ROLE, userDetails.getAuthorities()[0].getAuthority() );
            fail();
        } catch (BadCredentialsException ex) {
            assertTrue(true);
        }
    }

    /**
     * Setup the basic properties of our LdapPasswordAuthenticationDao
     */
    protected void setUp() {
        dao = new LdapPasswordAuthenticationDao();
        dao.setURL("ldap://localhost:389/ou=system");
    }

    /*
     * @todo:
     * 1. two different groups...
     * 2. two groups, limit 'roles'
     * 3. other stuff...
     */
}
