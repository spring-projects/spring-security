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

package org.acegisecurity.providers.dao.ldap;

import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.UserDetails;
import org.acegisecurity.providers.dao.ldap.support.BaseLdapTestCase;

import javax.naming.NamingException;


/**
 * Set of JUnit tests for the LdapPasswordAuthenticationDao.
 *
 * @author $author$
 * @version $Revision$
 */
public class LdapPasswordAuthenticationDaoTests extends BaseLdapTestCase {

    private LdapPasswordAuthenticationDao dao;
    private String DEFAULT_ROLE = "DEFAULT_ROLE";
    
    public static void main(String[] args) {
    	LdapPasswordAuthenticationDaoTests ats = new LdapPasswordAuthenticationDaoTests();
    	ats.setUp();
    	try {
    		ats.testSimpleUidUser();
    	} catch (Throwable t) {
    	    t.printStackTrace();
    	} finally {
    		System.exit(0);
    	}
    }

    
    /** Check to see that a user with no roles can not login 
     *  (this is the correct behavior the last time I checked the Acegi Docs).
     *
     */
    public void testEmptyRoles() {
        dao.setUsernameFormat("uid={0},ou=users,ou=system");

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("user.two",
                    "plaintext2");
            fail("No roles are accessible for user; this test _should_ fail.");
        } catch (BadCredentialsException ex) {
            assertTrue("No roles are accessible for user; this test _should_ fail.",
                ex.getMessage().startsWith(LdapPasswordAuthenticationDao.BAD_CREDENTIALS_EXCEPTION_MESSAGE));
        }
    }

    /** Test that the user who is identified by 
     * Common Name (cn=..) can be authenticated. */
    public void testSimpleCnUser() throws NamingException {
        dao.setUsernameFormat("cn={0},ou=users,ou=system");
        dao.setUserLookupNameFormat("cn={0},ou=users");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("User Two",
                    "plaintext2");
            assertEquals(1, userDetails.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails.getAuthorities()[0].getAuthority());
        } catch (BadCredentialsException ex) {
            fail();
        }
    }

    /** Test that the user who is identified by 
     * UID (uid=..) can be authenticated. */
    public void testSimpleUidUser() throws NamingException {
        dao.setUsernameFormat("uid={0},ou=users,ou=system");
        dao.setUserLookupNameFormat("uid={0},ou=users");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
        	System.out.println("Attempting user auth.");
        	
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("one.user",
                    "plaintext");
            
            //System.out.println( "UserDetails = " + userDetails );
            
            assertEquals(1, userDetails.getAuthorities().length);
            assertEquals(DEFAULT_ROLE,
                userDetails.getAuthorities()[0].getAuthority());
        } catch (BadCredentialsException ex) {
        	System.out.println("Unable to authenticate user.");
        	ex.printStackTrace();
            fail();
        }
    }

    /** Test that a login w/ a bad password fails. */
    public void testSimpleUidUserBadPassword() throws NamingException {
        dao.setUsernameFormat("uid={0},ou=users,ou=system");
        dao.setUserLookupNameFormat("uid={0},ou=users");
        dao.setDefaultRole(DEFAULT_ROLE);

        try {
            UserDetails userDetails = dao.loadUserByUsernameAndPassword("one.user",
                    "plainlywrong");
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
        dao.setUrl("ldap://localhost:389/ou=system");
    }

}
