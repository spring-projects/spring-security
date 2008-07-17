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
package org.springframework.security.userdetails.ldap;

import junit.framework.TestCase;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.userdetails.UserDetails;
import org.springframework.security.userdetails.UsernameNotFoundException;
import org.springframework.security.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.userdetails.memory.UserMap;
import org.springframework.security.userdetails.memory.UserMapEditor;

/**
 * @author Valery Tydykov
 * 
 */
public class ReplacingUserDetailsMapperTest extends TestCase {

    ReplacingUserDetailsMapper mapper;

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#setUp()
     */
    protected void setUp() throws Exception {
        mapper = new ReplacingUserDetailsMapper();
    }

    /*
     * (non-Javadoc)
     * 
     * @see junit.framework.TestCase#tearDown()
     */
    protected void tearDown() throws Exception {
        mapper = null;
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.ReplacingUserDetailsMapper#setUserDetailsService(org.springframework.security.userdetails.UserDetailsService)}.
     */
    public final void testSetUserDetailsServiceNullThrowsException() {
        try {
            mapper.setUserDetailsService(null);
            fail("exception expected");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.ReplacingUserDetailsMapper#setAccountMapper(org.springframework.security.userdetails.ldap.AccountMapper)}.
     */
    public final void testSetAccountMapperNullThrowsException() {
        try {
            mapper.setAccountMapper(null);
            fail("exception expected");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.ReplacingUserDetailsMapper#afterPropertiesSet()}.
     */
    public final void testAfterPropertiesSet() {
        try {
            mapper.afterPropertiesSet();
            fail("expected exception");
        } catch (IllegalArgumentException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.ReplacingUserDetailsMapper#mapUserFromContext(org.springframework.ldap.core.DirContextOperations, java.lang.String, org.springframework.security.GrantedAuthority[])}.
     */
    public final void testNormalOperation() {
        String userName = "rod,ok";
        UsernameFromPropertyAccountMapper accountMapper = new UsernameFromPropertyAccountMapper();
        accountMapper.setUsername(userName);
        mapper.setAccountMapper(accountMapper);
        mapper.setConvertToUpperCase(false);

        {
            // create secondary user accounts repository
            InMemoryDaoImpl dao = new InMemoryDaoImpl();
            UserMapEditor editor = new UserMapEditor();
            editor.setAsText("rod,ok=koala,ROLE_ONE,ROLE_TWO,enabled\r\n");
            dao.setUserMap((UserMap) editor.getValue());

            mapper.setUserDetailsService(dao);
        }

        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setAttributeValues("userRole", new String[] { "X", "Y", "Z" });
        ctx.setAttributeValue("uid", "ani");

        UserDetails userDetails = mapper.mapUserFromContext(ctx, "ani", new GrantedAuthority[0]);
        // verify that userDetails came from the secondary repository
        assertEquals("ROLE_ONE", userDetails.getAuthorities()[0].getAuthority());
    }

    /**
     * Test method for
     * {@link org.springframework.security.userdetails.ldap.ReplacingUserDetailsMapper#retrieveUser(java.lang.String)}.
     */
    public final void testRetrieveUser() {
        String username = "rod,ok";
        {
            // secondary user accounts repository
            InMemoryDaoImpl dao = new InMemoryDaoImpl();
            UserMapEditor editor = new UserMapEditor();
            editor.setAsText("rod,ok=koala,ROLE_ONE,ROLE_TWO,enabled\r\n");
            dao.setUserMap((UserMap) editor.getValue());

            mapper.setUserDetailsService(dao);
        }

        UserDetails userDetails = mapper.retrieveUser(username);

        assertEquals("ROLE_ONE", userDetails.getAuthorities()[0].getAuthority());

        try {
            mapper.retrieveUser("noMatchUsername");
            fail("exception expected");
        } catch (UsernameNotFoundException expected) {
        } catch (Exception unexpected) {
            fail("unexpected exception");
        }
    }
}
